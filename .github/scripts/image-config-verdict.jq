# "ok", or how the image config on stdin differs from $want: its entrypoint
# must prefix ENTRYPOINT+CMD and its imageEnv, nulls dropped, must equal Env.
def envmap: ((.config.Env // []) | map(split("=") | {key: .[0], value: (.[1:] | join("="))}) | from_entries);
((.config.Entrypoint // []) + (.config.Cmd // [])) as $argv
| $want.entrypoint as $ep
| ($want.imageEnv // {} | with_entries(select(.value != null) | .value |= tostring)) as $env
| if $argv[:($ep | length)] != $ep then "starts with \($argv | tojson), not the seeded entrypoint \($ep | tojson)"
  elif envmap != $env then "sets env \(envmap | tojson), not the seeded imageEnv \($env | tojson)"
  else "ok" end
