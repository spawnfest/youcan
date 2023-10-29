defmodule ExUcan.Core.Structs.UcanHeader do
  @moduledoc """
  Ucan header
  """
  @type t :: %__MODULE__{
          alg: String.t(),
          typ: String.t()
        }

  @derive Jason.Encoder
  defstruct [:alg, :typ]
end

defmodule ExUcan.Core.Structs.UcanPayload do
  @moduledoc """
  Ucan Payload
  """
  alias ExUcan.Core.Capability

  @type t :: %__MODULE__{
          ucv: String.t(),
          iss: String.t(),
          aud: String.t(),
          nbf: integer(),
          exp: integer(),
          nnc: String.t(),
          fct: map(),
          cap: list(Capability.t()),
          prf: list(String.t())
        }

  @derive Jason.Encoder
  defstruct [:ucv, :iss, :aud, :nbf, :exp, :nnc, :fct, :cap, :prf]
end

defmodule ExUcan.Core.Structs.Ucan do
  @moduledoc """
  UCAN struct
  """
  alias ExUcan.Core.Structs.UcanHeader
  alias ExUcan.Core.Structs.UcanPayload

  @type t :: %__MODULE__{
          header: UcanHeader.t(),
          payload: UcanPayload.t(),
          signed_data: String.t(),
          signature: String.t()
        }

  defstruct [:header, :payload, :signed_data, :signature]
end
