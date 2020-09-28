use crevise::{
    error::{bail, new_error},
    Result,
};
use std::{env, fs};
use std::{net::SocketAddr, path::PathBuf};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
pub struct Args {
    #[structopt(name = "LOCAL_SOCKET_ADDR", default_value = "127.0.0.1:8080")]
    pub listen: SocketAddr,

    #[structopt(short, long)]
    pub config_dir: Option<PathBuf>,

    #[structopt(short, long)]
    pub password: Option<String>,

    #[structopt(short, long)]
    pub generate_secret_key: bool,

    #[structopt(long)]
    pub show_my_id: bool,

    #[structopt(short, long)]
    known_peers: Option<PathBuf>,
}

pub fn parse_args() -> Result<Args> {
    let mut args: Args = Args::from_args();

    if args.password.is_none() {
        if let Ok(p) = env::var("CREVISE_PASSWORD") {
            args.password = Some(p);
        } else {
            bail!("password mut be provided either through env variable or argument",);
        }
    }

    let cfg = args
        .config_dir
        .take()
        .or_else(|| env::var_os("CREVISE_CONFIG_DIR").map(|p| p.into()))
        .or_else(|| env::var_os("HOME").map(|h| PathBuf::from(h).join(".crevise")))
        .or_else(|| Some(PathBuf::from(".crevise")))
        .ok_or(new_error!("Cannot get config dir"))?;

    if cfg.exists() && !cfg.is_dir() {
        bail!("config dir {:?} is not directory");
    } else if !cfg.exists() {
        fs::create_dir(&cfg)?;
    }
    args.config_dir = Some(cfg);

    Ok(args)
}

impl Args {
    pub fn known_peers(&self) -> PathBuf {
        self.known_peers
            .clone()
            .unwrap_or_else(|| self.config_dir.as_ref().unwrap().join("peers"))
    }

    pub fn password(&self) -> &str {
        self.password
            .as_ref()
            .expect("BUG: password not set")
            .as_str()
    }

    pub fn secret_key_file(&self) -> PathBuf {
        self.config_dir
            .as_ref()
            .expect("BUG: config dir not set")
            .join("secret_key")
    }
}
