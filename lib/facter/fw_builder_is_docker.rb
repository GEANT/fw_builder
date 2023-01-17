Facter.add(:fw_builder_is_docker) do
  setcode do
    if Facter::Util::Resolution.which('docker')
      true
    else
      false
    end
  end
end
