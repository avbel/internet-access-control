import logging
from datetime import timedelta

from homeassistant.components.switch import SwitchEntity
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.helpers.typing import ConfigType, DiscoveryInfoType

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)


async def async_setup_platform(
    hass: HomeAssistant,
    config: ConfigType,
    async_add_entities: AddEntitiesCallback,
    discovery_info: DiscoveryInfoType | None = None,
) -> None:
    data = hass.data[DOMAIN]
    base_url = f'http://{data["host"]}:{data["port"]}'
    scan_interval = data['scan_interval']
    session = async_get_clientsession(hass)
    tracked: dict[str, IACSwitch] = {}

    async def async_update(now=None):
        try:
            response = await session.get(f'{base_url}/statuses', timeout=10)
            if response.status != 200:
                _LOGGER.error(
                    'Failed to fetch statuses: HTTP %s', response.status
                )
                return
            result = await response.json()
        except Exception:
            _LOGGER.exception('Error fetching statuses from %s', base_url)
            return

        devices = {d['alias']: d for d in result.get('devices', [])}

        new_entities = []
        for alias, info in devices.items():
            if alias in tracked:
                tracked[alias].update_data(info['allowed'])
            else:
                entity = IACSwitch(
                    base_url, session, alias, info['mac'], info['allowed']
                )
                tracked[alias] = entity
                new_entities.append(entity)

        if new_entities:
            async_add_entities(new_entities)

        removed = set(tracked.keys()) - set(devices.keys())
        for alias in removed:
            entity = tracked.pop(alias)
            registry = er.async_get(hass)
            entity_id = registry.async_get_entity_id(
                'switch', DOMAIN, entity.unique_id
            )
            if entity_id:
                registry.async_remove(entity_id)

    await async_update()
    async_track_time_interval(
        hass, async_update, timedelta(seconds=scan_interval)
    )


class IACSwitch(SwitchEntity):
    _attr_has_entity_name = True

    def __init__(self, base_url, session, alias, mac, allowed):
        self._base_url = base_url
        self._session = session
        self._alias = alias
        self._mac = mac
        self._is_on = allowed
        self._attr_unique_id = f'iac_{alias}'
        self._attr_name = alias.replace('-', ' ').replace('_', ' ').title()
        self._attr_icon = 'mdi:web'

    @property
    def is_on(self) -> bool:
        return self._is_on

    @property
    def extra_state_attributes(self) -> dict:
        return {
            'mac_address': self._mac,
            'alias': self._alias,
        }

    def update_data(self, allowed: bool) -> None:
        self._is_on = allowed
        if self.hass:
            self.async_write_ha_state()

    async def async_turn_on(self, **kwargs) -> None:
        try:
            response = await self._session.post(
                f'{self._base_url}/rule',
                json={'device': self._alias, 'action': 'allow'},
                timeout=10,
            )
            if response.status == 200:
                self._is_on = True
                self.async_write_ha_state()
            else:
                _LOGGER.error(
                    'Failed to allow %s: HTTP %s', self._alias, response.status
                )
        except Exception:
            _LOGGER.exception('Error allowing %s', self._alias)

    async def async_turn_off(self, **kwargs) -> None:
        try:
            response = await self._session.post(
                f'{self._base_url}/rule',
                json={'device': self._alias, 'action': 'deny'},
                timeout=10,
            )
            if response.status == 200:
                self._is_on = False
                self.async_write_ha_state()
            else:
                _LOGGER.error(
                    'Failed to deny %s: HTTP %s', self._alias, response.status
                )
        except Exception:
            _LOGGER.exception('Error denying %s', self._alias)
