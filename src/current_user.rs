use std::any::Any;
use nickel::{Request, Response};
use nickel_session as session;
use plugin::Extensible;
use typemap::Key;
use std::marker::PhantomData;
use std::fmt::Debug;

pub trait SessionUser : session::Store {
    type User: Debug;
    type UserError: Debug;

    fn current_user(&mut Request<Self>, &mut Response<Self>) -> Result<Self::User, Self::UserError>;
}

// Plugin boilerplate
pub struct CachedCurrentUser<T: 'static + Any>(PhantomData<T>);
impl<D> Key for CachedCurrentUser<D>
where D: SessionUser + Any,
      D::User: Any {
        type Value = D::User;
}

pub struct CurrentUser;
impl CurrentUser {
    pub fn get<'a, D>(req: &mut Request<D>, res: &'a mut Response<D>) -> Result<&'a D::User, D::UserError>
    where D: SessionUser + Any,
          D::User: Any {
        use typemap::Entry::{Occupied, Vacant};

        if res.extensions().contains::<CachedCurrentUser<D>>() {
            return Ok(res.extensions_mut().get::<CachedCurrentUser<D>>().unwrap())
        }

        let user = try!(D::current_user(req, res));
        match res.extensions_mut().entry::<CachedCurrentUser<D>>() {
            Vacant(entry) => Ok(entry.insert(user)),
            Occupied(..) => unreachable!()
        }
    }
}
