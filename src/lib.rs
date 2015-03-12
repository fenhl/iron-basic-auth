#![feature(core)]

extern crate iron;

use std::error::Error;
use std::fmt;

use iron::prelude::*;
use iron::{headers, middleware, status};
use iron::typemap::TypeMap;

#[derive(Debug)]
struct AuthError;

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt("authentication error", f)
    }
}

impl Error for AuthError {
    fn description(&self) -> &str {
        "authentication error"
    }
}

pub trait CheckAuth {
    fn authorize(&self, user: &str, pass: &str) -> bool;

    #[allow(unused_variables)]
    fn wrong_credentials_error(&self, user: &str, pass: &str) -> &'static str {
        "Wrong username or password."
    }

    fn no_password_error(&self) -> &'static str {
        "No password found."
    }
}

pub struct SingleUser {
    username: String,
    password: String
}

impl CheckAuth for SingleUser {
    fn authorize(&self, user: &str, pass: &str) -> bool {
        user == self.username && pass == self.password
    }
}

impl CheckAuth for Fn(&str, &str) -> bool {
    fn authorize(&self, user: &str, pass: &str) -> bool {
        self(user, pass)
    }
}

impl middleware::BeforeMiddleware for CheckAuth + Send + Sync + 'static {
    fn before(&self, req: &mut Request) -> IronResult<()> {
        match req.headers.get::<headers::Authorization<headers::Basic>>() {
            Some(&headers::Authorization(headers::Basic { ref username, password: Some(ref password) })) => {
                if self.authorize(username, password) {
                    Ok(())
                } else {
                    Err(IronError {
                        error: Box::new(AuthError),
                        response: Response::with((status::Unauthorized, self.wrong_credentials_error(username, password)))
                    })
                }
            }
            Some(&headers::Authorization(headers::Basic { username: _, password: None })) => {
                Err(IronError {
                    error: Box::new(AuthError),
                    response: Response::with((status::Unauthorized, self.no_password_error()))
                })
            }
            None => {
                let mut hs = headers::Headers::new();
                hs.set_raw("WWW-Authenticate", vec![b"Basic realm=\"main\"".to_vec()]);
                Err(IronError {
                    error: Box::new(AuthError),
                    response: Response {
                        status: Some(status::Unauthorized),
                        headers: hs,
                        extensions: TypeMap::new(),
                        body: None
                    }
                })
            }
        }
    }
}
