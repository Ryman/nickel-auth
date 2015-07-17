#[macro_use] extern crate nickel;
#[macro_use] extern crate lazy_static;
extern crate rustc_serialize;
extern crate nickel_auth;
extern crate time;

use std::io::Write;
use nickel::*;
use nickel::status::StatusCode;
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

static SECRET_KEY: &'static cookies::SecretKey = &cookies::SecretKey([0; 32]);

impl AsRef<cookies::SecretKey> for ServerData {
    fn as_ref(&self) -> &cookies::SecretKey {
        SECRET_KEY
    }
}

impl SessionStore for ServerData {
    type Store = AppSession;

    fn timeout() -> Duration {
        Duration::seconds(5)
    }
}

impl SessionUser for ServerData {
    type User = User;

    fn current_user<'a>(res: &'a mut Response<Self>) -> Option<Self::User> {
        // Search the database for current user
        let user_id = res.session().user_id;

        user_id.and_then(|user_id| user::DATABASE.get(user_id as usize).cloned())

        // .. could fall back to looking `remember me` cookie here
    }
}


fn main() {
    let mut server = Nickel::with_data(ServerData);

    server.utilize(middleware! { |mut res| <ServerData>
        let login_attempts = res.session().login_attempts;
        let username = res.current_user().map(|user| user.name.clone());

        println!("access to '{:?}' by {:?} with {} login attempts",
                 res.request.origin.uri,
                 username,
                 login_attempts);
    });

    // Anyone should be able to reach this route.
    server.get("/", middleware! { |mut res|
        format!("You are logged in as: {:?}\n", res.current_user())
    });

    server.post("/login", middleware! { |mut res| <ServerData>
        #[derive(RustcDecodable, RustcEncodable, Debug)]
        struct LoginRequest {
            name: String,
            password: String,
        }

        res.session_mut().register_login_attempt();

        if let Ok(u) = res.request.json_as::<LoginRequest>() {
            // Search database for a matching login
            if let Some(id) = user::DATABASE.iter().position(|db| db.name == u.name
                                                          && db.password == u.password) {
                res.session_mut().user_id = Some(id as u64);

                return res.send("Successfully logged in.")
            }
        }

        (StatusCode::BadRequest, "Access denied.")
    });

    server.get("/secret", Authorize::any(vec![Permission::User(Access::Read, "foo".into())],
                                         middleware! { "Some hidden information!\n" }));

    fn custom_403<'a>(err: &mut NickelError<ServerData>) -> Action {
        if let Some(ref mut res) = err.response_mut() {
            if res.status() == StatusCode::Forbidden {
                let _ = res.write_all(b"Access denied!\n");
                return Halt(())
            }
        }

        Continue(())
    }

    // issue #20178
    let custom_handler: fn(&mut NickelError<ServerData>) -> Action = custom_403;

    server.handle_error(custom_handler);

    server.listen("127.0.0.1:6767");
}
