//! Who is an admin.

use std::ffi::CString;

use nix::unistd::{Gid, Group, Uid, User, getgrouplist};

pub fn name(uid: u32) -> String {
    User::from_uid(Uid::from_raw(uid))
        .ok()
        .flatten()
        .map_or_else(|| uid.to_string(), |u| u.name)
}

/// Root, or a member of one of `groups`.
pub fn is_admin(uid: u32, groups: &[String]) -> bool {
    if uid == 0 {
        return true;
    }
    let Some(user) = User::from_uid(Uid::from_raw(uid)).ok().flatten() else {
        return false;
    };
    let Ok(cname) = CString::new(user.name.clone()) else {
        return false;
    };
    let gids: Vec<Gid> = getgrouplist(&cname, user.gid).unwrap_or_else(|_| vec![user.gid]);
    gids.into_iter().any(|gid| {
        Group::from_gid(gid)
            .ok()
            .flatten()
            .is_some_and(|g| groups.contains(&g.name))
    })
}
