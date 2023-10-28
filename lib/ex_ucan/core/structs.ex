defmodule ExUcan.Core.Structs.UcanHeader do
  @moduledoc """
  Ucan header
  """

  @type t :: %__MODULE__{
          alg: String.t(),
          typ: String.t()
        }

  @derive Jason.Encoder
  defstruct(
    alg: "",
    typ: ""
  )

end

defmodule ExUcan.Core.Structs.UcanPayload do
  @moduledoc """
  Ucan Payload
  """

  @type t :: %__MODULE__{
          ucv: String.t(),
          iss: String.t(),
          aud: String.t(),
          nbf: integer(),
          exp: integer(),
          nnc: String.t(),
          fct: map(),
          cap: map(),
          prf: list(String.t())
        }

  @derive Jason.Encoder
  defstruct(
    ucv: "",
    iss: "",
    aud: "",
    nbf: 0,
    exp: nil,
    nnc: "",
    fct: %{},
    cap: %{},
    prf: []
  )
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

  @derive Jason.Encoder
  defstruct(
    header: nil,
    payload: nil,
    signed_data: "",
    signature: ""
  )
end
