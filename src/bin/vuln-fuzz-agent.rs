use std::{
    env,
    error::Error,
    ffi::OsString,
    fs, io,
    os::unix::{fs::PermissionsExt, net::UnixListener},
    path::PathBuf,
    process::ExitCode,
};

use vulnFuzz::agent::{Agent, AgentLimits, serve_stream};

const USAGE: &str =
    "Usage: vuln-fuzz-agent --workspace PATH (--socket PATH | --stdio) [--output-limit BYTES]";

fn run() -> Result<(), Box<dyn Error>> {
    let mut workspace = None;
    let mut socket = None;
    let mut stdio = false;
    let mut limits = AgentLimits::default();
    let mut arguments = env::args_os();
    arguments.next();
    while let Some(argument) = arguments.next() {
        match argument.to_str() {
            Some("--workspace") => {
                if workspace.is_some() {
                    return Err(USAGE.into());
                }
                workspace = Some(PathBuf::from(required_value(&mut arguments)?));
            }
            Some("--socket") => {
                if socket.is_some() {
                    return Err(USAGE.into());
                }
                socket = Some(PathBuf::from(required_value(&mut arguments)?));
            }
            Some("--stdio") => {
                if stdio {
                    return Err(USAGE.into());
                }
                stdio = true;
            }
            Some("--output-limit") => {
                let value = required_value(&mut arguments)?;
                limits.max_output_bytes = value
                    .to_str()
                    .and_then(|value| value.parse().ok())
                    .ok_or("--output-limit must be a nonnegative integer")?;
            }
            _ => return Err(USAGE.into()),
        }
    }
    let workspace = workspace.ok_or(USAGE)?;
    if socket.is_some() == stdio {
        return Err(USAGE.into());
    }
    let mut agent = Agent::new(workspace, limits)?;
    if let Some(socket) = socket {
        let listener = UnixListener::bind(&socket)?;
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
        let result = (|| {
            let (mut stream, _) = listener.accept()?;
            serve_stream(&mut stream, &mut agent)
        })();
        drop(listener);
        let _ = fs::remove_file(socket);
        result?;
    } else {
        let stdin = io::stdin();
        let stdout = io::stdout();
        let mut input = stdin.lock();
        let mut output = stdout.lock();
        let mut stream = StdioStream {
            input: &mut input,
            output: &mut output,
        };
        serve_stream(&mut stream, &mut agent)?;
    }
    Ok(())
}

fn required_value(arguments: &mut env::ArgsOs) -> Result<OsString, &'static str> {
    arguments.next().ok_or(USAGE)
}

struct StdioStream<'a> {
    input: &'a mut dyn io::Read,
    output: &'a mut dyn io::Write,
}

impl io::Read for StdioStream<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.input.read(buffer)
    }
}

impl io::Write for StdioStream<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.output.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("vuln-fuzz-agent: {error}");
            ExitCode::FAILURE
        }
    }
}
