use anyhow::{anyhow, Context as _};
use clap::Args;
use nix::unistd::Pid;
use rand::prelude::random;

use ockam::Context;

use crate::node::show::print_query_status;
use crate::node::util::run::CommandsRunner;
use crate::util::{connect_to, embedded_node};
use crate::{
    help,
    node::HELP_DETAIL,
    util::{exitcode, startup::spawn_node},
    CommandGlobalOpts,
};

/// Start Nodes
#[derive(Clone, Debug, Args)]
#[command(arg_required_else_help = true, after_long_help = help::template(HELP_DETAIL))]
pub struct StartCommand {
    /// Name of the node.
    #[arg(hide_default_value = true, default_value_t = hex::encode(&random::<[u8;4]>()))]
    node_name: String,
}

impl StartCommand {
    pub fn run(self, opts: CommandGlobalOpts) {
        if let Err(e) = run_impl(opts, self) {
            eprintln!("{}", e);
            std::process::exit(e.code());
        }
    }
}

fn run_impl(opts: CommandGlobalOpts, cmd: StartCommand) -> crate::Result<()> {
    let cfg = &opts.config;
    let cfg_node = cfg.get_node(&cmd.node_name)?;

    // First we check whether a PID was registered and if it is still alive.
    if let Some(pid) = cfg_node.pid() {
        // Note: On CI machines where <defunct> processes can occur,
        // the below `kill 0 pid` can imply a killed process is okay.
        let res = nix::sys::signal::kill(Pid::from_raw(pid), None);
        if res.is_ok() {
            return Err(crate::Error::new(
                exitcode::IOERR,
                anyhow!(
                    "Node '{}' already appears to be running as PID {}",
                    cmd.node_name,
                    pid
                ),
            ));
        }
    }

    embedded_node(restart_background_node, (opts.clone(), cmd.clone()))?;
    connect_to(
        cfg_node.port(),
        (cfg.clone(), cmd.node_name.clone(), true),
        print_query_status,
    );
    if let Ok(cfg) = cfg.node(&cmd.node_name) {
        CommandsRunner::run_node_startup(cfg.commands().config_path())
            .context("Failed to startup commands")?;
    }

    Ok(())
}

async fn restart_background_node(
    _ctx: Context,
    (opts, cmd): (CommandGlobalOpts, StartCommand),
) -> crate::Result<()> {
    let cfg = &opts.config;
    let cfg_node = cfg.get_node(&cmd.node_name)?;

    // Construct the arguments list and re-execute the ockam
    // CLI in foreground mode to start the newly created node
    spawn_node(
        &opts.config,
        cfg_node.verbose(),           // Previously user-chosen verbosity level
        true,                         // skip-defaults because the node already exists
        false,                        // Default value. TODO: implement persistence of this option
        false,                        // Default value. TODO: implement persistence of this option
        cfg_node.name(),              // The selected node name
        &cfg_node.addr().to_string(), // The selected node api address
        None,                         // No project information available
    )?;

    Ok(())
}
