#[macro_use] extern crate nickel;
extern crate plugin;
extern crate typemap;

pub use authorize::{Authorize, AuthorizeSession};
pub use current_user::{CurrentUser, SessionUser};
mod authorize;
mod current_user;
