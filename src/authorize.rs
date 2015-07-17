use std::any::Any;
use nickel::{Response, Middleware, MiddlewareResult};
use nickel::status::StatusCode::Forbidden;
use current_user::{SessionUser, CurrentUser};

pub trait AuthorizeSession {
    type Permissions;

    fn has_permission(Option<&Self>, permission: &Self::Permissions) -> bool;
}

pub struct Authorize<P, M> {
    access_granted: M,
    permissions: Permit<P>,
}

enum Permit<P> {
    Only(P),
    Any(Vec<P>),
    All(Vec<P>)
}

impl<P, M> Authorize<P, M> {
    pub fn only<D>(permission: P, access_granted: M) -> Authorize<P, M>
    where M: Middleware<D> + Send + Sync + 'static,
          D: SessionUser,
          D::Store: Any,
          D::User: AuthorizeSession<Permissions=P>,
          P: 'static + Send + Sync {
        Authorize {
            access_granted: access_granted,
            permissions: Permit::Only(permission),
        }
    }

    pub fn any<D>(permissions: Vec<P>, access_granted: M) -> Authorize<P, M>
    where M: Middleware<D> + Send + Sync + 'static,
          D: SessionUser,
          D::Store: Any,
          D::User: AuthorizeSession<Permissions=P>,
          P: 'static + Send + Sync {
        Authorize {
            access_granted: access_granted,
            permissions: Permit::Any(permissions),
        }
    }

    pub fn all<D>(permissions: Vec<P>, access_granted: M) -> Authorize<P, M>
    where M: Middleware<D> + Send + Sync + 'static,
          D: SessionUser,
          D::Store: Any,
          D::User: AuthorizeSession<Permissions=P>,
          P: 'static + Send + Sync {
        Authorize {
            access_granted: access_granted,
            permissions: Permit::All(permissions),
        }
    }
}

impl<P, M, D> Middleware<D> for Authorize<P, M>
where M: Middleware<D> + Send + Sync + 'static,
      D: SessionUser,
      D::Store: Any,
      D::User: AuthorizeSession<Permissions=P> + Any,
      P: 'static + Send + Sync {
    fn invoke<'a, 'b>(&'a self, mut res: Response<'a, 'b, D>) -> MiddlewareResult<'a, 'b, D> {
        let allowed = {
            let current_user = res.current_user();
            let check = <D::User as AuthorizeSession>::has_permission;
            match self.permissions {
                Permit::Only(ref p) => check(current_user, p),
                Permit::Any(ref ps) => ps.iter().any(|p| check(current_user, p)),
                Permit::All(ref ps) => ps.iter().all(|p| check(current_user, p)),
            }
        };

        if allowed {
            self.access_granted.invoke(res)
        } else {
            res.error(Forbidden, "Access denied.")
        }
    }
}
