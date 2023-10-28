defmodule ExUcan.Plugins.Ed25519.Keypair do
  @moduledoc """
  Encapsulates Ed25519 Keypair generation and other utilities
  """
  alias ExUcan.Core.Keymaterial
  alias ExUcan.Plugins.Ed25519.Crypto
  @behaviour Keymaterial
  # TODO: more doc..

  # TODO: Need type doc
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
  def create(exportable? \\ true)

  def create(exportable?) do
    {pub, priv} = :crypto.generate_key(:eddsa, :ed25519)
    %__MODULE__{
      jwt_alg: "EdDSA",
      secret_key: priv,
      public_key: pub,
      exportable: exportable?
    }
  end

  defimpl Keymaterial do
    def did(keypair) do
      Crypto.publickey_to_did(keypair.public_key)
    end

    def sign(keypair, payload) do
      :public_key.sign(payload, :ignored, {:ed_pri, :ed25519, keypair.public_key, keypair.secret_key}, [])
    end
  end
end
