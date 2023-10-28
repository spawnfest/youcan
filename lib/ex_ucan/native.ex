defmodule ExUcan.Native do
  # TODO Add doc
  @moduledoc """

  """

  use Rustler, otp_app: :ex_ucan, crate: "exucan_native"

  def add(_a, _b), do: :erlang.nif_error(:nif_not_loaded)
end
