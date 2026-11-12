//! Render the window into an image without a display (`wachposten window --screenshot x.png`),
//! for checking the design and for the README. Hidden from `--help`.

use std::path::Path;
use std::rc::Rc;

use anyhow::{Context, Result, bail};
use slint::platform::software_renderer::{
    MinimalSoftwareWindow, PremultipliedRgbaColor, RepaintBufferType,
};
use slint::platform::{Platform, WindowAdapter};

struct ShotPlatform(Rc<MinimalSoftwareWindow>);

impl Platform for ShotPlatform {
    fn create_window_adapter(&self) -> Result<Rc<dyn WindowAdapter>, slint::PlatformError> {
        Ok(self.0.clone())
    }
}

/// Use an off-screen window of this size for everything that follows.
pub fn install(width: u32, height: u32) -> Result<Rc<MinimalSoftwareWindow>> {
    let window = MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
    window.set_size(slint::PhysicalSize::new(width, height));
    slint::platform::set_platform(Box::new(ShotPlatform(window.clone())))
        .map_err(|e| anyhow::anyhow!("cannot set the off-screen platform: {e:?}"))?;
    Ok(window)
}

/// Draw the window and write it as PNG (through ImageMagick) or PPM.
pub fn save(window: &MinimalSoftwareWindow, path: &Path) -> Result<()> {
    slint::platform::update_timers_and_animations();
    let size = window.size();
    let (w, h) = (size.width as usize, size.height as usize);
    let mut buf = vec![PremultipliedRgbaColor::default(); w * h];
    window.request_redraw();
    if !window.draw_if_needed(|r| {
        r.render(&mut buf, w);
    }) {
        bail!("nothing was drawn");
    }
    let mut ppm = format!("P6\n{w} {h}\n255\n").into_bytes();
    for p in &buf {
        ppm.extend([p.red, p.green, p.blue]);
    }
    if path.extension().is_some_and(|e| e == "ppm") {
        std::fs::write(path, ppm)?;
        return Ok(());
    }
    let tmp = path.with_extension("ppm");
    std::fs::write(&tmp, ppm)?;
    let status = std::process::Command::new("magick")
        .arg(&tmp)
        .arg(path)
        .status()
        .context("ImageMagick (magick) is needed for PNG")?;
    let _ = std::fs::remove_file(&tmp);
    if !status.success() {
        bail!("magick failed");
    }
    Ok(())
}
