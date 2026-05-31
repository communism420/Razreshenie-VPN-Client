# -*- coding: utf-8 -*-
#
# Razreshenie VPN Client
# Copyright (C) 2026 Razreshenie VPN contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

"""Создает assets/app.ico для PyInstaller на основе logo.webp."""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "logo.webp"
TARGET = ROOT / "assets" / "app.ico"


def make_logo_icon(size: int) -> Image.Image:
    source = Image.open(SOURCE).convert("RGBA")
    source.thumbnail((size, size), Image.Resampling.LANCZOS)
    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    x = (size - source.width) // 2
    y = (size - source.height) // 2
    image.alpha_composite(source, (x, y))
    return image


def make_icon(size: int) -> Image.Image:
    if SOURCE.exists():
        return make_logo_icon(size)

    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    scale = size / 256

    def box(values: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
        return tuple(int(v * scale) for v in values)

    draw.rounded_rectangle(box((0, 0, 256, 256)), radius=int(56 * scale), fill="#121a23")
    draw.ellipse(box((70, 50, 186, 166)), fill="#18d6a3")
    draw.rounded_rectangle(box((103, 104, 153, 196)), radius=int(20 * scale), fill="#18d6a3")
    draw.arc(box((78, 52, 178, 152)), start=180, end=360, fill="#0c1117", width=max(4, int(22 * scale)))
    draw.ellipse(box((114, 112, 142, 140)), fill="#0c1117")
    draw.rounded_rectangle(box((122, 136, 134, 166)), radius=int(6 * scale), fill="#0c1117")
    return image


def main() -> None:
    TARGET.parent.mkdir(parents=True, exist_ok=True)
    sizes = [make_icon(size) for size in (16, 24, 32, 48, 64, 128, 256)]
    sizes[-1].save(TARGET, sizes=[(img.width, img.height) for img in sizes], append_images=sizes[:-1])
    print(f"Icon written: {TARGET}")


if __name__ == "__main__":
    main()
