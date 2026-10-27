#[cfg(target_os = "linux")]
pub fn apply() -> anyhow::Result<()> {
    use anyhow::Context;
    use nix::sys::prctl;
    use nix::sys::resource::{setrlimit, Resource};

    setrlimit(Resource::RLIMIT_CORE, 0, 0).context("disabling core dumps")?;
    prctl::set_dumpable(false).context("marking process non-dumpable")?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn apply() -> anyhow::Result<()> {
    tracing::warn!("process hardening is only available on Linux");
    Ok(())
}
