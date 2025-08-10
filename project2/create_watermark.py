#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
创建简单水印图片的辅助脚本
"""

import cv2
import numpy as np


def create_simple_watermark(text="COPYRIGHT", width=100, height=50, output_path="watermark.png"):
    """
    创建一个简单的文字水印图片

    参数:
    text: 水印文字
    width: 水印宽度
    height: 水印高度
    output_path: 输出文件路径
    """
    # 创建黑色背景
    watermark = np.zeros((height, width), dtype=np.uint8)

    # 添加白色文字
    font = cv2.FONT_HERSHEY_SIMPLEX
    font_scale = 0.5
    font_thickness = 1
    text_color = 255  # 白色

    # 计算文字位置（居中）
    text_size = cv2.getTextSize(text, font, font_scale, font_thickness)[0]
    text_x = (width - text_size[0]) // 2
    text_y = (height + text_size[1]) // 2

    # 绘制文字
    cv2.putText(watermark, text, (text_x, text_y), font, font_scale, text_color, font_thickness)

    # 保存水印
    cv2.imwrite(output_path, watermark)
    print(f"水印图片已创建: {output_path}")
    print(f"尺寸: {width} x {height}")


def create_logo_watermark(output_path="logo_watermark.png"):
    """创建一个简单的logo式水印"""
    watermark = np.zeros((64, 64), dtype=np.uint8)

    # 画一个简单的图案
    cv2.circle(watermark, (32, 32), 25, 255, 2)
    cv2.circle(watermark, (32, 32), 15, 255, -1)
    cv2.putText(watermark, "WM", (22, 37), cv2.FONT_HERSHEY_SIMPLEX, 0.7, 0, 2)

    cv2.imwrite(output_path, watermark)
    print(f"Logo水印已创建: {output_path}")
    print(f"尺寸: 64 x 64")


if __name__ == "__main__":
    # 创建两种水印供选择
    create_simple_watermark("MY MARK", 120, 40, "text_watermark.png")
    create_logo_watermark("logo_watermark.png")