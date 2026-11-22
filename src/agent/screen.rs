//! A lock event invalidates the current generation even if the desktop
//! unlocks again before the server loop gets a turn. Unlocking the desktop
//! never restores agent keys.
use anyhow::{Result, ensure};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

#[derive(Clone, Default)]
pub(super) struct Screen(Arc<AtomicU64>);

impl Screen {
    pub(super) fn ticket(&self) -> Result<u64> {
        let n = self.0.load(Ordering::Acquire);
        ensure!(n & 1 == 0, "desktop session is locked or unavailable");
        Ok(n)
    }

    fn update(&self, locked: bool) {
        // Each platform has one writer; tickets can be read by any worker.
        if (self.0.load(Ordering::Relaxed) & 1 != 0) != locked {
            self.0.fetch_add(1, Ordering::AcqRel);
        }
    }
}

pub(super) use platform::Monitor;

#[cfg(target_os = "macos")]
mod platform {
    use super::*;
    use anyhow::Context;
    use core_foundation::{
        base::{CFType, TCFType},
        boolean::CFBoolean,
        dictionary::{CFDictionary, CFDictionaryRef},
        runloop::{CFRunLoopRunInMode, kCFRunLoopDefaultMode},
        string::CFString,
    };
    use core_foundation_sys::notification_center::*;
    use std::{
        ffi::c_void,
        ptr,
        time::{Duration, Instant},
    };

    #[link(name = "CoreGraphics", kind = "framework")]
    unsafe extern "C" {
        fn CGSessionCopyCurrentDictionary() -> CFDictionaryRef;
    }

    fn locked() -> Result<bool> {
        let raw = unsafe { CGSessionCopyCurrentDictionary() };
        ensure!(
            !raw.is_null(),
            "machine-lock requires a macOS GUI login session"
        );
        let dict: CFDictionary<CFString, CFType> =
            unsafe { CFDictionary::wrap_under_create_rule(raw) };
        let flag = |name| -> Result<Option<bool>> {
            dict.find(CFString::from_static_string(name))
                .map(|v| {
                    let b = v
                        .downcast::<CFBoolean>()
                        .context("invalid macOS session flag")?;
                    Ok(bool::from(b))
                })
                .transpose()
        };
        Ok(
            !flag("kCGSSessionOnConsoleKey")?.context("no macOS console session")?
                || flag("CGSSessionScreenIsLocked")?.unwrap_or(false),
        )
    }

    extern "C" fn on_lock(
        _: CFNotificationCenterRef,
        observer: *mut c_void,
        _: CFNotificationName,
        _: *const c_void,
        _: CFDictionaryRef,
    ) {
        // The boxed observer outlives registration; delivery and removal take
        // place on the daemon's main run loop.
        unsafe { &*observer.cast::<Screen>() }.update(true);
    }

    pub(in crate::agent) struct Monitor {
        observer: Box<Screen>,
        last_check: Instant,
    }

    impl Monitor {
        pub(in crate::agent) fn start(screen: Screen) -> Result<Self> {
            let observer = Box::new(screen);
            let name = CFString::from_static_string("com.apple.screenIsLocked");
            let center = unsafe { CFNotificationCenterGetDistributedCenter() };
            ensure!(!center.is_null(), "macOS session notifications unavailable");
            unsafe {
                CFNotificationCenterAddObserver(
                    center,
                    ptr::from_ref(&*observer).cast(),
                    on_lock,
                    name.as_concrete_TypeRef(),
                    ptr::null(),
                    CFNotificationSuspensionBehaviorDeliverImmediately,
                );
            }
            let monitor = Self {
                observer,
                last_check: Instant::now(),
            };
            monitor.observer.update(locked()?);
            Ok(monitor)
        }

        pub(in crate::agent) fn tick(&mut self) {
            unsafe {
                CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.0, 0);
            }
            if self.last_check.elapsed() >= Duration::from_millis(250) {
                self.observer.update(locked().unwrap_or(true));
                self.last_check = Instant::now();
            }
        }
    }

    impl Drop for Monitor {
        fn drop(&mut self) {
            unsafe {
                CFNotificationCenterRemoveEveryObserver(
                    CFNotificationCenterGetDistributedCenter(),
                    ptr::from_ref(&*self.observer).cast(),
                );
            }
        }
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    use anyhow::{Context, bail};
    use std::thread;
    use zbus::{
        MatchRule,
        blocking::{Connection, MessageIterator, fdo::DBusProxy},
        message::Type,
    };

    pub(in crate::agent) struct Monitor;

    impl Monitor {
        pub(in crate::agent) fn start(screen: Screen) -> Result<Self> {
            let conn =
                Connection::session().context("machine-lock requires a desktop session bus")?;
            let bus = DBusProxy::new(&conn)?;
            for (service, path) in [
                (
                    "org.freedesktop.ScreenSaver",
                    "/org/freedesktop/ScreenSaver",
                ),
                ("org.freedesktop.ScreenSaver", "/ScreenSaver"),
                ("org.gnome.ScreenSaver", "/org/gnome/ScreenSaver"),
                ("org.cinnamon.ScreenSaver", "/org/cinnamon/ScreenSaver"),
                ("org.mate.ScreenSaver", "/org/mate/ScreenSaver"),
            ] {
                let Ok(owner) = bus.get_name_owner(service.try_into()?) else {
                    continue;
                };
                let active = || -> zbus::Result<bool> {
                    conn.call_method(Some(owner.as_str()), path, Some(service), "GetActive", &())?
                        .body()
                        .deserialize()
                };
                if active().is_err() {
                    continue;
                }
                // Subscribe before taking the initial state; bind to the actual
                // provider and fail closed if it loses its bus name.
                let iter = MessageIterator::from(&conn);
                bus.add_match_rule(
                    MatchRule::builder()
                        .msg_type(Type::Signal)
                        .sender(owner.as_str())?
                        .path(path)?
                        .interface(service)?
                        .member("ActiveChanged")?
                        .build(),
                )?;
                bus.add_match_rule(
                    MatchRule::builder()
                        .msg_type(Type::Signal)
                        .sender("org.freedesktop.DBus")?
                        .interface("org.freedesktop.DBus")?
                        .member("NameOwnerChanged")?
                        .add_arg(service)?
                        .build(),
                )?;
                ensure!(
                    bus.get_name_owner(service.try_into()?)? == owner,
                    "screen locker changed during startup"
                );
                screen.update(active()?);
                thread::Builder::new()
                    .name("desktop-lock".into())
                    .spawn(move || {
                        for msg in iter {
                            let Ok(msg) = msg else { break };
                            let h = msg.header();
                            if h.message_type() != Type::Signal {
                                continue;
                            }
                            match (
                                h.sender().map(|s| s.as_str()),
                                h.member().map(|m| m.as_str()),
                            ) {
                                (Some("org.freedesktop.DBus"), Some("NameOwnerChanged")) => break,
                                (Some(sender), Some("ActiveChanged"))
                                    if sender == owner.as_str()
                                        && h.path().is_some_and(|p| p.as_str() == path)
                                        && h.interface().is_some_and(|i| i.as_str() == service) =>
                                {
                                    let Ok(active) = msg.body().deserialize::<bool>() else {
                                        break;
                                    };
                                    screen.update(active);
                                }
                                _ => (),
                            }
                        }
                        screen.update(true);
                    })?;
                return Ok(Self);
            }
            bail!("machine-lock requires a desktop exposing a supported ScreenSaver D-Bus service")
        }

        pub(in crate::agent) fn tick(&mut self) {}
    }
}
