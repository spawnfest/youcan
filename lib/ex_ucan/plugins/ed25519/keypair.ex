defmodule ExUcan.Plugins.Ed25519.Keypair do
  @moduledoc """
  Encapsulates Ed25519 Keypair generation and other utilities
  """
  # TODO: more doc..

  @type t :: %__MODULE__{
    jwt_alg: String.t(),
    secret_key: binary(),
    public_key: binary(),
    exportable: boolean()
  }

  defstruct(
    jwt_alg: "EdDSA",
    secret_key: <<>>,
    public_key: <<>>,
    exportable: false
  )

  @spec create(boolean()) :: __MODULE__.t()
  def create(exportable?) do
    {pub, priv} = :crypto.generate_key(:eddsa, :ed25519)
    __MODULE__.__struct__(
      jwt_alg: "EdDSA",
      secret_key: priv,
      public_key: pub,
      exportable: exportable?
    )
  end

end
