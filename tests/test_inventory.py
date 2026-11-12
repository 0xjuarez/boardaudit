"""Inventory structure tests. Hardware may be absent in CI/VM."""

from boardaudit.inventory import inventory, list_network_adapters, list_serial_ports, list_usb_devices


def test_inventory_shape():
    data = inventory()
    assert set(data) == {"system", "serial_ports", "usb_devices", "network_adapters"}
    assert isinstance(data["serial_ports"], list)
    assert isinstance(data["usb_devices"], list)
    assert isinstance(data["network_adapters"], list)


def test_serial_ports_are_dicts():
    for port in list_serial_ports():
        assert "device" in port


def test_network_adapters_are_dicts():
    for adapter in list_network_adapters():
        assert "name" in adapter


def test_usb_devices_are_strings():
    for device in list_usb_devices():
        assert isinstance(device, str)
