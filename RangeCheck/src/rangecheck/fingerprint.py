from __future__ import annotations

import asyncio
import logging
import ssl

LOGGER = logging.getLogger(__name__)


async def fingerprint_service(host: str, port: int, service_name: str) -> str | None:
    """Perform lightweight HTTP/HTTPS header fingerprinting."""
    use_ssl = service_name in ("https", "https-alt") or port == 443

    try:
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx),
                timeout=3.0,
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=3.0,
            )

        request = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        writer.write(request.encode())
        await writer.drain()

        data = await asyncio.wait_for(reader.read(4096), timeout=3.0)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        if data:
            raw = data.decode("utf-8", errors="replace")
            headers: list[str] = []

            for line in raw.split("\r\n"):
                lower = line.lower()
                if any(
                    lower.startswith(h)
                    for h in ("server:", "x-powered-by:", "x-aspnet-version:")
                ):
                    headers.append(line.strip())

            return "; ".join(headers) if headers else None

        return None

    except (asyncio.TimeoutError, ConnectionRefusedError, OSError, ssl.SSLError) as exc:
        LOGGER.debug("Fingerprint failed for %s:%d — %s", host, port, exc)
        return None
