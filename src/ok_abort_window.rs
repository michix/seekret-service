use std::rc::Rc;
use std::{borrow::BorrowMut, cell::RefCell};

use log::debug;
use winsafe::{co, gui};

#[derive(Clone)]
pub struct OkAbortWindow {
    wnd: gui::WindowMain,
    button_abort: gui::Button,
    button_okay: gui::Button,

    aborted: Rc<RefCell<bool>>,
}

impl OkAbortWindow {
    pub fn new(window_title: String, message: String) -> Self {
        let wnd = gui::WindowMain::new(gui::WindowMainOpts {
            title: window_title,
            class_icon: gui::Icon::Id(101),
            size: (240, 120),
            ..Default::default()
        });

        let btn_okay = gui::Button::new(
            &wnd,
            gui::ButtonOpts {
                text: "&Okay".to_owned(),
                position: (130, 80),
                ..Default::default()
            },
        );

        let btn_abort = gui::Button::new(
            &wnd,
            gui::ButtonOpts {
                text: "&Abort".to_owned(),
                position: (20, 80),
                ..Default::default()
            },
        );

        let _ = gui::Label::new(
            &wnd,
            gui::LabelOpts {
                position: (20, 20),
                size: (200, 60),
                text: message,
                ..Default::default()
            },
        );

        let new_self = Self {
            wnd,
            button_abort: btn_abort,
            button_okay: btn_okay,
            aborted: Rc::new(RefCell::new(true)),
        };

        debug!("Attaching events...");
        new_self.events();
        debug!("Done attaching events");
        new_self
    }

    pub fn run(&self) -> Result<bool, bool> {
        debug!("Before run on OkAbortWindow...");
        let _ = self.wnd.run_main(None);
        debug!("After run on OkAbortWindow...");
        if self.is_aborted() {
            debug!("Is aborted");
            Err(true)
        } else {
            debug!("Is not aborted");
            Ok(true)
        }
    }

    fn events(&self) {
        let self2 = self.clone();
        self.button_abort.on().bn_clicked(move || {
            self2.wnd.close();
            Ok(())
        });
        let self3 = self.clone();
        self.button_okay.on().bn_clicked(move || {
            self3.ok();
            self3.wnd.close();
            Ok(())
        });
        let self4 = self.clone();
        self.button_okay.on_subclass().wm_key_up(move |key| {
            if key.vkey_code == co::VK::RETURN {
                self4.button_okay.trigger_click();
            } else if key.vkey_code == co::VK::ESCAPE {
                self4.button_abort.trigger_click();
            }
            Ok(())
        });
    }

    fn ok(&self) {
        self.clone().aborted.borrow_mut().replace(false);
    }

    fn is_aborted(&self) -> bool {
        *self.aborted.borrow()
    }
}
