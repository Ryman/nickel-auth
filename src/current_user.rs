use std::any::Any;
use nickel::{Response, SessionStore};
use plugin::{Plugin, Pluggable};
use typemap::Key;
use std::marker::PhantomData;

pub trait SessionUser : SessionStore {
    type User;

    fn current_user(&mut Response<Self>) -> Option<Self::User>;
}

pub trait CurrentUser {
    type User;

    fn current_user(&mut self) -> Option<&Self::User>;
}

impl<'a, 'k, D> CurrentUser for Response<'a, 'k, D>
    where D: SessionUser,
          D::User: Any {
    type User = D::User;

    fn current_user(&mut self) -> Option<&Self::User> {
        self.get_ref::<CurrentUserPlugin<Self::User>>().ok()
    }
}

// Plugin boilerplate
pub struct CurrentUserPlugin<T: 'static + Any>(PhantomData<T>);
impl<T: 'static + Any> Key for CurrentUserPlugin<T> { type Value = T; }

impl<'a, 'k, D, T> Plugin<Response<'a, 'k, D>> for CurrentUserPlugin<T>
where T: 'static + Any,
      D: SessionUser<User=T> {
    type Error = ();

    fn eval(res: &mut Response<'a, 'k, D>) -> Result<T, ()> {
        <D as SessionUser>::current_user(res).ok_or(())
    }
}
