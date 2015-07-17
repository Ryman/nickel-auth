use nickel_auth::AuthorizeSession;

// Imitation database
lazy_static! {
    pub static ref DATABASE: Vec<User> = vec![
        User { name: "foo".into(), password: "bar".into(), is_admin: false },
        User { name: "admin".into(), password: "password".into(), is_admin: true }
    ];
}

#[derive(RustcDecodable, RustcEncodable, Debug, Clone)]
pub struct User {
    pub name: String,
    pub password: String,
    pub is_admin: bool,
}

#[derive(Eq, PartialEq)]
#[allow(dead_code)]
pub enum Permission {
    Public,
    // Can read given users profile
    User(Access, String),
    Admin
}

#[derive(Eq, PartialEq, Copy, Clone)]
#[allow(dead_code)]
pub enum Access {
    Read,
    Write
}

impl AuthorizeSession for User {
    type Permissions = Permission;

    fn has_permission(current_user: Option<&Self>, requirement: &Permission) -> bool {
        use user::Access::*;

        match current_user {
            Some(&User { ref name, is_admin, .. }) => {
                match *requirement {
                    Permission::User(Read, ref profile_name) => {
                        name == profile_name || is_admin
                    },
                    Permission::User(Write, ref profile_name) => {
                        name == profile_name
                    },
                    Permission::Admin => is_admin,
                    Permission::Public => true
                }
            }
            None => Permission::Public == *requirement
        }
    }
}
