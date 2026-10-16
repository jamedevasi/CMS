"""KAN-11 (input validation / output encoding against XSS) and KAN-12 (parameterized queries).

Jinja autoescaping encodes every value a template prints, every SQL statement in db.py
binds its values with placeholders, and the two gaps a review found are closed here:
`next` redirects only go to pages inside Feast9, and a doctor's calendar colour (printed
into a style attribute) must be a plain #rrggbb code."""
import pytest

from app import db
from app.auth import safe_next_url
from tests.conftest import get_csrf, register_patient, search_patients

SCRIPT = '<script>alert("x")</script>'
SQL = "x' OR '1'='1' --"


# ── Output encoding (XSS) ───────────────────────────────────────────────────

def test_patient_name_is_html_escaped_on_detail_and_list(logged_in_client):
    patient_id = register_patient(logged_in_client, name=SCRIPT)
    for body in (
        logged_in_client.get(f"/patients/{patient_id}").get_data(as_text=True),
        logged_in_client.get("/patients/?view=all").get_data(as_text=True),
    ):
        assert SCRIPT not in body
        assert "&lt;script&gt;" in body


def test_json_data_island_cannot_close_its_script_tag(logged_in_client):
    """Analytics hands chart data to JS in a <script type="application/json"> block —
    `tojson` must encode '<' so a name containing '</script>' can't end that block."""
    doctor_id = db.add_doctor("</script><script>alert(1)</script>", "#123456")
    patient = db.add_patient({"name": "Chart Patient", "sex": "Male", "dpdp_notice_accepted": 1})
    db.add_case({"patient_id": patient, "doctor_id": doctor_id, "title": "Filling", "total_cost": 100})
    body = logged_in_client.get("/analytics/").get_data(as_text=True)
    island = body.split('id="analytics-data">')[1].split("</script>")[0]
    assert "<script>" not in island and "</script" not in island


# ── Parameterized queries (SQL injection) ───────────────────────────────────

def test_sql_metacharacters_in_search_match_nothing(logged_in_client):
    register_patient(logged_in_client, name="Ordinary Person")
    body = search_patients(logged_in_client, SQL, view="all")
    assert "Ordinary Person" not in body


def test_sql_metacharacters_are_stored_verbatim(logged_in_client):
    patient_id = register_patient(logged_in_client, name=SQL)
    assert db.get_patient(patient_id)["name"] == SQL
    assert len(db.list_patients()) == 1  # nothing else created, nothing dropped


# ── Redirects after sign-in stay inside Feast9 ──────────────────────────────

@pytest.mark.parametrize("target", [
    "https://evil.example/",
    "//evil.example/",
    "/\\evil.example/",
    "javascript:alert(1)",
    "http://evil.example/patients/",
    "/patients/\r\nSet-Cookie: x=1",
])
def test_external_next_urls_fall_back_to_dashboard(app, target):
    with app.test_request_context("/", base_url="http://localhost"):
        assert safe_next_url(target) == "/dashboard"


@pytest.mark.parametrize("target, expected", [
    ("/patients/?view=all", "/patients/?view=all"),
    ("/users/new?", "/users/new"),                      # request.full_path's trailing '?'
    ("http://localhost/backup/", "/backup/"),            # a same-host Referer
    (None, "/dashboard"),
    ("", "/dashboard"),
])
def test_local_next_urls_are_kept(app, target, expected):
    with app.test_request_context("/", base_url="http://localhost"):
        assert safe_next_url(target) == expected


def test_login_does_not_redirect_off_site(setup_admin):
    token = get_csrf(setup_admin, "/login")
    resp = setup_admin.post(
        "/login?next=https://evil.example/phish",
        data={"username": "admin", "password": "testpass123", "csrf_token": token},
    )
    assert resp.status_code == 302
    assert "evil.example" not in resp.headers["Location"]


def test_login_still_returns_to_the_requested_page(setup_admin):
    token = get_csrf(setup_admin, "/login")
    resp = setup_admin.post(
        "/login?next=/appointments/",
        data={"username": "admin", "password": "testpass123", "csrf_token": token},
    )
    assert resp.headers["Location"].endswith("/appointments/")


# ── Doctor colour (printed into a style attribute) ──────────────────────────

def test_doctor_colour_must_be_a_hex_code(logged_in_client):
    token = get_csrf(logged_in_client, "/doctors/")
    resp = logged_in_client.post("/doctors/new", data={
        "name": "Dr. Css", "color": "red; background-image: url(https://evil.example/x)", "csrf_token": token,
    }, follow_redirects=True)
    assert "colour code" in resp.get_data(as_text=True)
    assert not [d for d in db.list_doctors(active_only=False) if d["name"] == "Dr. Css"]


def test_doctor_colour_edit_rejects_css(logged_in_client):
    doctor_id = db.add_doctor("Dr. Edit", "#123456")
    token = get_csrf(logged_in_client, f"/doctors/{doctor_id}/edit")
    logged_in_client.post(f"/doctors/{doctor_id}/edit", data={
        "name": "Dr. Edit", "color": "#123456;}body{display:none", "csrf_token": token,
    })
    assert db.get_doctor(doctor_id)["color"] == "#123456"


def test_valid_and_blank_doctor_colours_are_accepted(logged_in_client):
    token = get_csrf(logged_in_client, "/doctors/")
    logged_in_client.post("/doctors/new", data={"name": "Dr. Hex", "color": "#A1b2C3", "csrf_token": token})
    token = get_csrf(logged_in_client, "/doctors/")
    logged_in_client.post("/doctors/new", data={"name": "Dr. Blank", "color": "", "csrf_token": token})
    names = {d["name"] for d in db.list_doctors(active_only=False)}
    assert {"Dr. Hex", "Dr. Blank"} <= names
