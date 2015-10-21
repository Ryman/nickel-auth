#[macro_use] extern crate lazy_static;
#[macro_use] extern crate nickel;
extern crate nickel_cookies;
extern crate nickel_session;
extern crate nickel_auth;
extern crate rustc_serialize;
extern crate time;

use std::io::Write;
use nickel::*;
use nickel::status::StatusCode;
use nickel_session as session;
use nickel_session::{Session, CookieSession};
use nickel_cookies as cookies;
use nickel_auth::{Authorize, CurrentUser, SessionUser};
use time::Duration;

use user::{User, Access, Permission};

mod user;

struct ServerData;

#[derive(RustcDecodable, RustcEncodable, Debug, Default)]
struct AppSession {
    login_attempts: u64,
    user_id: Option<u64>
}

impl AppSession {
    fn register_login_attempt(&mut self) {
        self.login_attempts += 1;
    }
}

impl cookies::KeyProvider for ServerData {}

impl session::Store for ServerData {
    type Session = AppSession;

    fn timeout() -> Duration {
        Duration::seconds(5)
    }
}

impl SessionUser for ServerData {
    type User = User;
    type UserError = ();

    fn current_user(req: &mut Request<Self>, res: &mut Response<Self>) -> Result<Self::User, Self::UserError> {
        // Search the database for current user
        let user_id = CookieSession::get_mut(req, res).user_id;

        user_id.and_then(|user_id| user::DATABASE.get(user_id as usize).cloned()).ok_or(())

        // .. could fall back to looking `remember me` cookie here
    }
}


fn main() {
    let mut server = Nickel::with_data(ServerData);

    server.utilize(middleware! { |req, mut res| <ServerData>
        let login_attempts = CookieSession::get_mut(req, &mut res).login_attempts;
        let username = CurrentUser::get(req, &mut res).map(|user| &user.name);

        println!("access to '{:?}' by {:?} with {} login attempts",
                 req.origin.uri,
                 username,
                 login_attempts);
    });

    // Anyone should be able to reach this route.
    server.get("/", middleware! { |req, mut res|
        format!("You are logged in as: {:?}\n", CurrentUser::get(req, &mut res).ok())
    });

    server.post("/login", middleware! { |req, mut res| <ServerData>
        #[derive(RustcDecodable, RustcEncodable, Debug)]
        struct LoginRequest {
            name: String,
            password: String,
        }

        CookieSession::get_mut(req, &mut res).register_login_attempt();

        if let Ok(u) = req.json_as::<LoginRequest>() {
            // Search database for a matching login
            if let Some(id) = user::DATABASE.iter().position(|db| db.name == u.name
                                                          && db.password == u.password) {
                CookieSession::get_mut(req, &mut res).user_id = Some(id as u64);

                return res.send("Successfully logged in.")
            }
        }

        (StatusCode::BadRequest, "Access denied.")
    });

    server.get("/secret", Authorize::any(vec![Permission::User(Access::Read, "foo".into())],
                                         middleware! { "Some hidden information!\n" }));

    fn custom_403<'a>(err: &mut NickelError<ServerData>, _: &mut Request<ServerData>) -> Action {
        if let Some(ref mut res) = err.stream {
            if res.status() == StatusCode::Forbidden {
                let _ = res.write_all(b"Access denied!\n");
                return Halt(())
            }
        }

        Continue(())
    }

    // issue #20178
    let custom_handler: fn(&mut NickelError<ServerData>, &mut Request<ServerData>) -> Action = custom_403;

    server.handle_error(custom_handler);

    server.listen("127.0.0.1:6767");
}
