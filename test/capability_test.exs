defmodule CapabilityTest do
  alias ExUcan.Core.Capabilities
  alias ExUcan.Core.Capability
  use ExUnit.Case

  @tag :caps
  test "can_cast_between_map_and_sequence" do
    cap_foo = Capability.new("example//foo", "ability/foo", %{})
    assert cap_foo.caveat == %{}
    cap_bar = Capability.new("example://bar", "ability/bar", %{"beep" => 1})

    cap_sequence = [cap_foo, cap_bar]

    cap_maps = Capabilities.sequence_to_map(cap_sequence)
    assert Capabilities.map_to_sequence(cap_maps) == cap_sequence
  end

  test "it_rejects_non_compliant_json" do
    failure_cases = [
      {
        [],
        "resources must be map"
      },
      {
        %{"resource:foo" => []},
        "abilities must be map"
      },
      {
        %{"resource:foo" => {}},
        "resource must have at least one ability"
      },
      {
        %{"resource:foo" => %{"ability/read" => %{}}},
        "caveats must be a list"
      },
      {
        %{"resource:foo" => %{"ability/read" => [1]}},
        "caveat must be object"
      }
    ]
  end
end
