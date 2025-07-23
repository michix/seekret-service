use std::rc::Rc;
use std::{borrow::BorrowMut, cell::RefCell};

use winsafe::{co, gui};

#[derive(Clone)]
pub struct PasswordWindow {
    wnd: gui::WindowMain,
    button_abort: gui::Button,
    button_okay: gui::Button,
    text_input: gui::Edit,

    aborted: Rc<RefCell<bool>>,
    input_text: Rc<RefCell<String>>,
}

impl PasswordWindow {
    pub fn new(window_title: String) -> Self {
        let wnd = gui::WindowMain::new(gui::WindowMainOpts {
            title: window_title,
            class_icon: gui::Icon::Id(101),
            size: (500, 130),
            style: co::WS::OVERLAPPEDWINDOW,
            ..Default::default()
        });

        let txt_input = gui::Edit::new(
            &wnd,
            gui::EditOpts {
                width: 460,
                control_style: co::ES::AUTOHSCROLL | co::ES::PASSWORD,
                position: (20, 20),
                resize_behavior: (gui::Horz::Resize, gui::Vert::None),
                ..Default::default()
            },
        );

        let btn_abort = gui::Button::new(
            &wnd,
            gui::ButtonOpts {
                text: "&Abort".to_owned(),
                position: (20, 60),
                ..Default::default()
            },
        );

        let btn_okay = gui::Button::new(
            &wnd,
            gui::ButtonOpts {
                text: "&Okay".to_owned(),
                position: (130, 60),
                ..Default::default()
            },
        );

        let new_self = Self {
            wnd,
            button_abort: btn_abort,
            button_okay: btn_okay,
            text_input: txt_input,
            aborted: Rc::new(RefCell::new(false)),
            input_text: Rc::new(RefCell::new(String::from(""))),
        };

        new_self.events();
        new_self
    }

    pub fn run(&self) -> Result<String, bool> {
        let _ = self.wnd.run_main(None);
        if self.is_aborted() {
            Err(self.is_aborted())
        } else {
            Ok(self.get_input_text())
        }
    }

    fn events(&self) {
        let self2 = self.clone();
        self.button_abort.on().bn_clicked(move || {
            self2.abort();
            self2.wnd.close();
            Ok(())
        });
        let self3 = self.clone();
        self.button_okay.on().bn_clicked(move || {
            self3.set_input_text(
                self3
                    .text_input
                    .text()
                    .clone()
                    .expect("Could not clone input text!"),
            );
            self3.wnd.close();
            Ok(())
        });
        let self4 = self.clone();
        self.text_input.on().en_err_space(move || {
            println!("Got Update!");
            Ok(())
        });
        self.text_input.on_subclass().wm_key_up(move |key| {
            if key.vkey_code == co::VK::RETURN {
                self4.button_okay.trigger_click();
            } else if key.vkey_code == co::VK::ESCAPE {
                self4.button_abort.trigger_click();
            }
            Ok(())
        });
    }

    fn abort(&self) {
        self.clone().aborted.borrow_mut().replace(true);
    }

    fn is_aborted(&self) -> bool {
        *self.aborted.borrow()
    }

    fn set_input_text(&self, input_text: String) {
        self.clone().input_text.borrow_mut().replace(input_text);
    }

    fn get_input_text(&self) -> String {
        self.clone().input_text.borrow().to_string()
    }
}
