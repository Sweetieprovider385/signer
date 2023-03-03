#[macro_use]
extern crate rocket;

#[get("/upcheck")]
fn upcheck() -> &'static str {
    "OK"
}

#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![upcheck])
}
