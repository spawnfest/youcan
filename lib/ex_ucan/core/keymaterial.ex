# TODO: docs??

defprotocol ExUcan.Core.Keymaterial do
  alias ExUcan.Core.Structs.UcanPayload
  @spec did(struct()) :: String.t()
  def did(type)

  @spec sign(struct(), UcanPayload.t()) :: binary()
  def sign(type, payload)
end
