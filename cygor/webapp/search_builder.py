"""
SQLAlchemy query builder for advanced search.

Converts parsed search filters into SQLAlchemy queries.
"""

import re
import ipaddress
from typing import List, Dict, Any, Optional
from sqlalchemy import select, or_, and_, not_, func
from sqlalchemy.orm import selectinload
from sqlmodel.ext.asyncio.session import AsyncSession

from .models import Host, Port, Script, OSGuess


class SearchQueryBuilder:
    """Build SQLAlchemy queries from parsed search filters."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def build_host_query(self, filters: Dict[str, Any], case_insensitive: bool = False):
        """Build query for hosts based on filters."""
        query = select(Host).options(
            selectinload(Host.ports),
            selectinload(Host.scripts),
            selectinload(Host.os_guesses)
        )

        conditions = []

        # IP address filters
        if filters.get('ip_addresses'):
            ip_conditions = []
            for ip_filter in filters['ip_addresses']:
                value = ip_filter['value']
                if case_insensitive:
                    condition = func.lower(Host.address).contains(func.lower(value))
                else:
                    condition = Host.address.contains(value)

                if ip_filter.get('negated'):
                    condition = not_(condition)
                ip_conditions.append(condition)

            if ip_conditions:
                conditions.append(or_(*ip_conditions))

        # CIDR range filters
        if filters.get('cidr_ranges'):
            cidr_conditions = []
            for cidr_filter in filters['cidr_ranges']:
                network = cidr_filter['network']
                # Convert CIDR to SQL BETWEEN condition for performance
                # This is a simplification; for production, consider inet type in PostgreSQL
                network_str = str(network.network_address)
                broadcast_str = str(network.broadcast_address)

                condition = Host.address.between(network_str, broadcast_str)

                if cidr_filter.get('negated'):
                    condition = not_(condition)
                cidr_conditions.append(condition)

            if cidr_conditions:
                conditions.append(or_(*cidr_conditions))

        # Hostname filters
        if filters.get('hostnames'):
            hostname_conditions = []
            for hostname_filter in filters['hostnames']:
                value = hostname_filter['value']
                if hostname_filter.get('regex'):
                    # PostgreSQL regex
                    condition = Host.hostname.op('~')(value)
                else:
                    if case_insensitive:
                        condition = func.lower(Host.hostname).contains(func.lower(value))
                    else:
                        condition = Host.hostname.contains(value)

                if hostname_filter.get('negated'):
                    condition = not_(condition)
                hostname_conditions.append(condition)

            if hostname_conditions:
                conditions.append(or_(*hostname_conditions))

        # OS filters (join with OSGuess)
        if filters.get('os_filters'):
            os_conditions = []
            for os_filter in filters['os_filters']:
                value = os_filter['value']

                if os_filter.get('regex'):
                    subquery = select(OSGuess.host_id).where(
                        OSGuess.name.op('~')(value)
                    )
                else:
                    if case_insensitive:
                        subquery = select(OSGuess.host_id).where(
                            func.lower(OSGuess.name).contains(func.lower(value))
                        )
                    else:
                        subquery = select(OSGuess.host_id).where(
                            OSGuess.name.contains(value)
                        )

                condition = Host.id.in_(subquery)

                if os_filter.get('negated'):
                    condition = not_(condition)
                os_conditions.append(condition)

            if os_conditions:
                conditions.append(or_(*os_conditions))

        # General search terms (apply to address, hostname, or related port service/protocol)
        if filters.get('terms'):
            term_conditions = []
            for term in filters['terms']:
                value = term['value']

                # Create subquery to check if host has ports matching the term
                if case_insensitive:
                    port_subquery = select(Port.host_id).where(
                        or_(
                            func.lower(Port.service).contains(func.lower(value)),
                            func.lower(Port.protocol).contains(func.lower(value)),
                            func.lower(Port.banner).contains(func.lower(value))
                        )
                    )
                    term_cond = or_(
                        func.lower(Host.address).contains(func.lower(value)),
                        func.lower(Host.hostname).contains(func.lower(value)),
                        Host.id.in_(port_subquery)
                    )
                else:
                    port_subquery = select(Port.host_id).where(
                        or_(
                            Port.service.contains(value),
                            Port.protocol.contains(value),
                            Port.banner.contains(value)
                        )
                    )
                    term_cond = or_(
                        Host.address.contains(value),
                        Host.hostname.contains(value),
                        Host.id.in_(port_subquery)
                    )

                if term.get('negated'):
                    term_cond = not_(term_cond)
                term_conditions.append(term_cond)

            if term_conditions:
                conditions.append(or_(*term_conditions))

        # Apply all conditions
        if conditions:
            query = query.where(and_(*conditions))

        return query

    async def build_port_query(self, filters: Dict[str, Any], case_insensitive: bool = False):
        """Build query for ports based on filters."""
        query = select(Port).options(selectinload(Port.host))

        conditions = []

        # Port number filters
        if filters.get('ports'):
            port_conditions = []
            for port_filter in filters['ports']:
                value = port_filter['value']
                condition = Port.port == value

                if port_filter.get('negated'):
                    condition = not_(condition)
                port_conditions.append(condition)

            if port_conditions:
                conditions.append(or_(*port_conditions))

        # Port range filters
        if filters.get('port_ranges'):
            range_conditions = []
            for range_filter in filters['port_ranges']:
                min_port = range_filter['min']
                max_port = range_filter['max']
                condition = Port.port.between(min_port, max_port)

                if range_filter.get('negated'):
                    condition = not_(condition)
                range_conditions.append(condition)

            if range_conditions:
                conditions.append(or_(*range_conditions))

        # Service filters
        if filters.get('services'):
            service_conditions = []
            for service_filter in filters['services']:
                value = service_filter['value']

                if service_filter.get('regex'):
                    condition = Port.service.op('~')(value)
                else:
                    if case_insensitive:
                        condition = func.lower(Port.service).contains(func.lower(value))
                    else:
                        condition = Port.service.contains(value)

                if service_filter.get('negated'):
                    condition = not_(condition)
                service_conditions.append(condition)

            if service_conditions:
                conditions.append(or_(*service_conditions))

        # Banner filters
        if filters.get('banners'):
            banner_conditions = []
            for banner_filter in filters['banners']:
                value = banner_filter['value']

                if banner_filter.get('regex'):
                    condition = and_(Port.banner.isnot(None), Port.banner.op('~')(value))
                else:
                    if case_insensitive:
                        condition = and_(
                            Port.banner.isnot(None),
                            func.lower(Port.banner).contains(func.lower(value))
                        )
                    else:
                        condition = and_(
                            Port.banner.isnot(None),
                            Port.banner.contains(value)
                        )

                if banner_filter.get('negated'):
                    condition = not_(condition)
                banner_conditions.append(condition)

            if banner_conditions:
                conditions.append(or_(*banner_conditions))

        # Protocol filters
        if filters.get('protocols'):
            protocol_conditions = []
            for protocol_filter in filters['protocols']:
                value = protocol_filter['value']
                condition = Port.protocol == value

                if protocol_filter.get('negated'):
                    condition = not_(condition)
                protocol_conditions.append(condition)

            if protocol_conditions:
                conditions.append(or_(*protocol_conditions))

        # General search terms (apply to service or banner)
        if filters.get('terms'):
            term_conditions = []
            for term in filters['terms']:
                value = term['value']
                if case_insensitive:
                    term_cond = or_(
                        func.lower(Port.service).contains(func.lower(value)),
                        and_(
                            Port.banner.isnot(None),
                            func.lower(Port.banner).contains(func.lower(value))
                        )
                    )
                else:
                    term_cond = or_(
                        Port.service.contains(value),
                        and_(
                            Port.banner.isnot(None),
                            Port.banner.contains(value)
                        )
                    )

                if term.get('negated'):
                    term_cond = not_(term_cond)
                term_conditions.append(term_cond)

            if term_conditions:
                conditions.append(or_(*term_conditions))

        # Apply all conditions
        if conditions:
            query = query.where(and_(*conditions))

        return query

    async def build_script_query(self, filters: Dict[str, Any], case_insensitive: bool = False):
        """Build query for scripts based on filters."""
        query = select(Script).options(
            selectinload(Script.host),
            selectinload(Script.port)
        )

        conditions = []

        # Script name filters
        if filters.get('scripts'):
            script_conditions = []
            for script_filter in filters['scripts']:
                value = script_filter['value']

                if script_filter.get('regex'):
                    condition = Script.name.op('~')(value)
                else:
                    if case_insensitive:
                        condition = func.lower(Script.name).contains(func.lower(value))
                    else:
                        condition = Script.name.contains(value)

                if script_filter.get('negated'):
                    condition = not_(condition)
                script_conditions.append(condition)

            if script_conditions:
                conditions.append(or_(*script_conditions))

        # Status code filters (for Lockon results)
        if filters.get('status_codes'):
            status_conditions = []
            for status_filter in filters['status_codes']:
                value = status_filter['value']
                condition = Script.status_code == value

                if status_filter.get('negated'):
                    condition = not_(condition)
                status_conditions.append(condition)

            if status_conditions:
                conditions.append(or_(*status_conditions))

        # General search terms (apply to output)
        if filters.get('terms'):
            term_conditions = []
            for term in filters['terms']:
                value = term['value']
                if case_insensitive:
                    term_cond = func.lower(Script.output).contains(func.lower(value))
                else:
                    term_cond = Script.output.contains(value)

                if term.get('negated'):
                    term_cond = not_(term_cond)
                term_conditions.append(term_cond)

            if term_conditions:
                conditions.append(or_(*term_conditions))

        # Apply all conditions
        if conditions:
            query = query.where(and_(*conditions))

        return query

    def apply_sorting(self, query, model, sort_by: str):
        """Apply sorting to query."""
        if not sort_by or sort_by == 'relevance':
            # Default relevance sorting (by ID)
            return query.order_by(model.id)

        if model == Host:
            if sort_by == 'ip_asc':
                # For proper IP sorting, use inet type in PostgreSQL
                # For now, simple text sorting
                return query.order_by(Host.address.asc())
            elif sort_by == 'ip_desc':
                return query.order_by(Host.address.desc())

        elif model == Port:
            if sort_by == 'port_asc':
                return query.order_by(Port.port.asc())
            elif sort_by == 'port_desc':
                return query.order_by(Port.port.desc())

        return query

    def apply_pagination(self, query, page: int, per_page: int):
        """Apply database-level pagination."""
        offset = (page - 1) * per_page
        return query.offset(offset).limit(per_page)
