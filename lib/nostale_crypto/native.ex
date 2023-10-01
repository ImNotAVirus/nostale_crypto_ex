defmodule NostaleCrypto.Native do
  @moduledoc false

  mix_config = Mix.Project.config()
  version = mix_config[:version]
  github_url = mix_config[:package][:links]["GitHub"]
  # Since Rustler 0.27.0, we need to change manually the mode for each env.
  # We want "debug" in dev and test because it's faster to compile.
  mode = if Mix.env() in [:dev, :test], do: :debug, else: :release

  use RustlerPrecompiled,
    otp_app: :nostale_crypto,
    crate: "nostale_crypto",
    version: version,
    base_url: "#{github_url}/releases/download/v#{version}",
    mode: mode,
    force_build: System.get_env("NOSTALECRYPTO_BUILD") in ["1", "true"]

  # Public API

  @spec login_next(binary()) :: {binary() | nil, binary()}
  def login_next(_raw), do: err()

  @spec login_encrypt(String.t()) :: binary()
  def login_encrypt(_raw), do: err()

  @spec login_decrypt(binary()) :: String.t()
  def login_decrypt(_raw), do: err()

  @spec world_next(binary(), byte()) :: {binary() | nil, binary()}
  def world_next(_raw, _key), do: err()

  @spec world_encrypt(String.t()) :: binary()
  def world_encrypt(_raw), do: err()

  @spec world_decrypt(binary()) :: String.t()
  def world_decrypt(_raw), do: err()

  # Helpers

  defp err(), do: :erlang.nif_error(:nif_not_loaded)
end
