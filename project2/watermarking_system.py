#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced Digital Watermarking System
====================================

A comprehensive image watermarking solution implementing LSB (Least Significant Bit)
steganography with advanced robustness testing capabilities.

Author: Enhanced Implementation
Version: 2.0
"""

import cv2
import numpy as np
import os
import argparse
import logging
from pathlib import Path
from typing import Tuple, Optional, Union
from dataclasses import dataclass
from enum import Enum
import json
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('watermark_system.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class ProcessingMode(Enum):
    """定义图像处理模式枚举"""
    EMBEDDING = "embedding"
    EXTRACTION = "extraction"
    ROBUSTNESS_TEST = "robustness_analysis"


@dataclass
class ImageMetadata:
    """图像元数据类"""
    height: int
    width: int
    channels: int
    file_path: str
    file_size: int

    @classmethod
    def from_image_path(cls, image_path: str) -> 'ImageMetadata':
        """从图像路径创建元数据对象"""
        if not os.path.exists(image_path):
            raise FileNotFoundError(f"图像文件不存在: {image_path}")

        img = cv2.imread(image_path)
        if img is None:
            raise ValueError(f"无法读取图像文件: {image_path}")

        h, w, c = img.shape
        file_size = os.path.getsize(image_path)

        return cls(h, w, c, image_path, file_size)


@dataclass
class WatermarkConfig:
    """水印配置类"""
    threshold_value: int = 128
    bit_depth: int = 1
    color_channels: int = 3
    binary_white: int = 1
    binary_black: int = 0
    output_scale: int = 255


class ImageProcessor:
    """图像处理器基类"""

    def __init__(self, config: WatermarkConfig = None):
        self.config = config or WatermarkConfig()
        logger.info("图像处理器初始化完成")

    def load_image(self, path: str, mode: int = cv2.IMREAD_COLOR) -> np.ndarray:
        """安全地加载图像文件"""
        try:
            image_data = cv2.imread(path, mode)
            if image_data is None:
                raise IOError(f"图像加载失败: {path}")
            logger.debug(f"成功加载图像: {path}, 尺寸: {image_data.shape}")
            return image_data
        except Exception as e:
            logger.error(f"图像加载错误: {e}")
            raise

    def save_image(self, image: np.ndarray, output_path: str, quality: int = 95) -> bool:
        """保存图像到指定路径"""
        try:
            # 确保输出目录存在
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)

            # 根据文件扩展名选择保存参数
            if output_path.lower().endswith('.jpg') or output_path.lower().endswith('.jpeg'):
                save_params = [cv2.IMWRITE_JPEG_QUALITY, quality]
            else:
                save_params = []

            success = cv2.imwrite(output_path, image, save_params)
            if success:
                logger.info(f"图像已保存: {output_path}")
                return True
            else:
                logger.error(f"图像保存失败: {output_path}")
                return False
        except Exception as e:
            logger.error(f"保存图像时发生错误: {e}")
            return False

    def convert_to_binary(self, grayscale_image: np.ndarray) -> np.ndarray:
        """将灰度图像转换为二值数组"""
        _, binary_data = cv2.threshold(
            grayscale_image,
            self.config.threshold_value,
            self.config.binary_white,
            cv2.THRESH_BINARY
        )
        return binary_data


class LSBWatermarkEmbedder(ImageProcessor):
    """LSB水印嵌入器"""

    def __init__(self, config: WatermarkConfig = None):
        super().__init__(config)
        self.embedding_statistics = {}

    def validate_embedding_capacity(self, host_dims: Tuple[int, int, int],
                                    watermark_dims: Tuple[int, int]) -> bool:
        """验证宿主图像是否有足够容量嵌入水印"""
        host_pixels = host_dims[0] * host_dims[1] * host_dims[2]
        watermark_bits = watermark_dims[0] * watermark_dims[1]

        if watermark_bits > host_pixels:
            logger.error(f"容量不足: 需要 {watermark_bits} 位，但只有 {host_pixels} 位可用")
            return False

        logger.info(f"容量验证通过: {watermark_bits}/{host_pixels} 位")
        return True

    def preprocess_watermark(self, watermark_image: np.ndarray) -> np.ndarray:
        """预处理水印图像"""
        binary_watermark = self.convert_to_binary(watermark_image)
        flattened_bits = binary_watermark.flatten()

        logger.info(f"水印预处理完成: {len(flattened_bits)} 个比特")
        self.embedding_statistics['watermark_bits'] = len(flattened_bits)

        return flattened_bits

    def perform_lsb_embedding(self, host_image: np.ndarray,
                              watermark_bits: np.ndarray) -> np.ndarray:
        """执行LSB嵌入操作"""
        modified_image = host_image.copy()
        height, width, channels = host_image.shape
        bit_counter = 0
        watermark_length = len(watermark_bits)

        # 嵌入循环
        for row_idx in range(height):
            for col_idx in range(width):
                for channel_idx in range(channels):
                    if bit_counter < watermark_length:
                        current_pixel = modified_image[row_idx, col_idx, channel_idx]
                        watermark_bit = watermark_bits[bit_counter]

                        # LSB替换操作
                        modified_pixel = self._replace_lsb(current_pixel, watermark_bit)
                        modified_image[row_idx, col_idx, channel_idx] = modified_pixel

                        bit_counter += 1
                    else:
                        break
                if bit_counter >= watermark_length:
                    break
            if bit_counter >= watermark_length:
                break

        self.embedding_statistics['embedded_bits'] = bit_counter
        logger.info(f"LSB嵌入完成: {bit_counter} 个比特已嵌入")

        return modified_image

    def _replace_lsb(self, pixel_value: int, bit_value: int) -> int:
        """替换像素的最低有效位"""
        # 清除最低位并设置新的比特值
        modified_pixel = (pixel_value & 0b11111110) | bit_value
        return modified_pixel

    def embed_watermark_in_image(self, host_path: str, watermark_path: str,
                                 output_path: str) -> bool:
        """主要的水印嵌入接口"""
        try:
            logger.info(f"开始水印嵌入: {host_path} + {watermark_path} -> {output_path}")

            # 加载图像
            host_image = self.load_image(host_path, cv2.IMREAD_COLOR)
            watermark_image = self.load_image(watermark_path, cv2.IMREAD_GRAYSCALE)

            # 验证容量
            if not self.validate_embedding_capacity(host_image.shape, watermark_image.shape):
                return False

            # 预处理水印
            watermark_bits = self.preprocess_watermark(watermark_image)

            # 执行嵌入
            watermarked_image = self.perform_lsb_embedding(host_image, watermark_bits)

            # 保存结果
            success = self.save_image(watermarked_image, output_path)

            if success:
                logger.info("水印嵌入流程完成")
                self._save_embedding_metadata(output_path, watermark_image.shape)

            return success

        except Exception as e:
            logger.error(f"水印嵌入过程中发生错误: {e}")
            return False

    def _save_embedding_metadata(self, output_path: str, watermark_dims: Tuple[int, int]):
        """保存嵌入元数据"""
        metadata = {
            'timestamp': datetime.now().isoformat(),
            'watermark_dimensions': watermark_dims,
            'embedding_statistics': self.embedding_statistics,
            'config': {
                'threshold': self.config.threshold_value,
                'bit_depth': self.config.bit_depth
            }
        }

        metadata_path = output_path.replace('.png', '_metadata.json').replace('.jpg', '_metadata.json')
        try:
            with open(metadata_path, 'w', encoding='utf-8') as f:
                json.dump(metadata, f, indent=2, ensure_ascii=False)
            logger.debug(f"元数据已保存: {metadata_path}")
        except Exception as e:
            logger.warning(f"保存元数据失败: {e}")


class LSBWatermarkExtractor(ImageProcessor):
    """LSB水印提取器"""

    def __init__(self, config: WatermarkConfig = None):
        super().__init__(config)
        self.extraction_statistics = {}

    def extract_lsb_bits(self, watermarked_image: np.ndarray,
                         total_bits_needed: int) -> np.ndarray:
        """从图像中提取LSB比特"""
        height, width, channels = watermarked_image.shape
        extracted_bits = []

        for row_idx in range(height):
            for col_idx in range(width):
                for channel_idx in range(channels):
                    if len(extracted_bits) < total_bits_needed:
                        pixel_value = watermarked_image[row_idx, col_idx, channel_idx]
                        lsb_bit = self._extract_lsb(pixel_value)
                        extracted_bits.append(lsb_bit)
                    else:
                        break
                if len(extracted_bits) >= total_bits_needed:
                    break
            if len(extracted_bits) >= total_bits_needed:
                break

        logger.info(f"LSB比特提取完成: {len(extracted_bits)} 个比特")
        self.extraction_statistics['extracted_bits'] = len(extracted_bits)

        return np.array(extracted_bits)

    def _extract_lsb(self, pixel_value: int) -> int:
        """提取像素的最低有效位"""
        return pixel_value & 1

    def reconstruct_watermark(self, bit_array: np.ndarray,
                              target_dimensions: Tuple[int, int]) -> np.ndarray:
        """重构水印图像"""
        height, width = target_dimensions
        required_bits = height * width

        if len(bit_array) < required_bits:
            raise ValueError(f"比特数量不足: 需要 {required_bits}，但只有 {len(bit_array)}")

        # 重塑为二维数组
        watermark_matrix = bit_array[:required_bits].reshape((height, width))

        # 转换为显示格式
        display_watermark = (watermark_matrix * self.config.output_scale).astype(np.uint8)

        logger.info(f"水印重构完成: {target_dimensions}")
        return display_watermark

    def extract_watermark_from_image(self, watermarked_path: str,
                                     watermark_dimensions: Tuple[int, int],
                                     output_path: str) -> bool:
        """主要的水印提取接口"""
        try:
            logger.info(f"开始水印提取: {watermarked_path} -> {output_path}")

            # 加载带水印的图像
            watermarked_image = self.load_image(watermarked_path, cv2.IMREAD_COLOR)

            # 计算需要提取的比特数
            total_bits = watermark_dimensions[0] * watermark_dimensions[1]

            # 提取LSB比特
            extracted_bits = self.extract_lsb_bits(watermarked_image, total_bits)

            # 重构水印
            reconstructed_watermark = self.reconstruct_watermark(extracted_bits, watermark_dimensions)

            # 保存提取的水印
            success = self.save_image(reconstructed_watermark, output_path)

            if success:
                logger.info("水印提取流程完成")

            return success

        except Exception as e:
            logger.error(f"水印提取过程中发生错误: {e}")
            return False


class SimilarityAnalyzer:
    """相似度分析器"""

    def __init__(self, threshold: int = 128):
        self.threshold = threshold

    def compute_pixel_accuracy(self, original_path: str, extracted_path: str) -> float:
        """计算两个水印图像的像素准确率"""
        try:
            original_img = cv2.imread(original_path, cv2.IMREAD_GRAYSCALE)
            extracted_img = cv2.imread(extracted_path, cv2.IMREAD_GRAYSCALE)

            if original_img is None or extracted_img is None:
                logger.error("无法加载比较图像")
                return 0.0

            if original_img.shape != extracted_img.shape:
                logger.error(f"图像尺寸不匹配: {original_img.shape} vs {extracted_img.shape}")
                return 0.0

            # 二值化处理
            _, original_binary = cv2.threshold(original_img, self.threshold, 255, cv2.THRESH_BINARY)
            _, extracted_binary = cv2.threshold(extracted_img, self.threshold, 255, cv2.THRESH_BINARY)

            # 计算匹配度
            matching_pixels = np.sum(original_binary == extracted_binary)
            total_pixels = original_img.size

            accuracy = (matching_pixels / total_pixels) * 100
            logger.debug(f"相似度分析: {matching_pixels}/{total_pixels} = {accuracy:.2f}%")

            return accuracy

        except Exception as e:
            logger.error(f"相似度计算错误: {e}")
            return 0.0


class RobustnessTestSuite:
    """鲁棒性测试套件"""

    def __init__(self, output_directory: str = "robustness_analysis"):
        self.output_dir = Path(output_directory)
        self.output_dir.mkdir(exist_ok=True)
        self.extractor = LSBWatermarkExtractor()
        self.analyzer = SimilarityAnalyzer()
        self.test_results = {}

    def execute_comprehensive_tests(self, watermarked_path: str,
                                    original_watermark_path: str,
                                    watermark_dimensions: Tuple[int, int]) -> dict:
        """执行全面的鲁棒性测试"""
        logger.info("启动鲁棒性测试套件")

        test_scenarios = [
            ("baseline_control", self._baseline_test),
            ("horizontal_flip", self._horizontal_flip_test),
            ("geometric_translation", self._translation_test),
            ("region_cropping", self._cropping_test),
            ("contrast_enhancement", self._contrast_test),
            ("jpeg_compression", self._compression_test)
        ]

        for test_name, test_function in test_scenarios:
            logger.info(f"执行测试: {test_name}")
            try:
                accuracy = test_function(watermarked_path, original_watermark_path, watermark_dimensions)
                self.test_results[test_name] = accuracy
                logger.info(f"{test_name} 测试完成: {accuracy:.2f}%")
            except Exception as e:
                logger.error(f"{test_name} 测试失败: {e}")
                self.test_results[test_name] = 0.0

        self._generate_test_report()
        return self.test_results

    def _baseline_test(self, watermarked_path: str, original_wm_path: str,
                       wm_dims: Tuple[int, int]) -> float:
        """基线测试（无攻击）"""
        extracted_path = self.output_dir / "baseline_extracted.png"
        self.extractor.extract_watermark_from_image(watermarked_path, wm_dims, str(extracted_path))
        return self.analyzer.compute_pixel_accuracy(original_wm_path, str(extracted_path))

    def _horizontal_flip_test(self, watermarked_path: str, original_wm_path: str,
                              wm_dims: Tuple[int, int]) -> float:
        """水平翻转攻击测试"""
        img = cv2.imread(watermarked_path)
        flipped_img = cv2.flip(img, 1)

        attacked_path = self.output_dir / "attacked_horizontal_flip.png"
        extracted_path = self.output_dir / "extracted_horizontal_flip.png"

        cv2.imwrite(str(attacked_path), flipped_img)
        self.extractor.extract_watermark_from_image(str(attacked_path), wm_dims, str(extracted_path))
        return self.analyzer.compute_pixel_accuracy(original_wm_path, str(extracted_path))

    def _translation_test(self, watermarked_path: str, original_wm_path: str,
                          wm_dims: Tuple[int, int]) -> float:
        """几何平移攻击测试"""
        img = cv2.imread(watermarked_path)
        h, w = img.shape[:2]

        # 平移参数
        translation_x, translation_y = 45, 35
        transformation_matrix = np.float32([[1, 0, translation_x], [0, 1, translation_y]])
        translated_img = cv2.warpAffine(img, transformation_matrix, (w, h))

        attacked_path = self.output_dir / "attacked_translation.png"
        extracted_path = self.output_dir / "extracted_translation.png"

        cv2.imwrite(str(attacked_path), translated_img)
        self.extractor.extract_watermark_from_image(str(attacked_path), wm_dims, str(extracted_path))
        return self.analyzer.compute_pixel_accuracy(original_wm_path, str(extracted_path))

    def _cropping_test(self, watermarked_path: str, original_wm_path: str,
                       wm_dims: Tuple[int, int]) -> float:
        """区域裁剪攻击测试"""
        img = cv2.imread(watermarked_path)
        h, w = img.shape[:2]

        # 保留75%的区域
        crop_ratio = 0.75
        cropped_img = img[0:int(h * crop_ratio), 0:int(w * crop_ratio)]

        attacked_path = self.output_dir / "attacked_cropping.png"
        extracted_path = self.output_dir / "extracted_cropping.png"

        cv2.imwrite(str(attacked_path), cropped_img)

        try:
            self.extractor.extract_watermark_from_image(str(attacked_path), wm_dims, str(extracted_path))
            return self.analyzer.compute_pixel_accuracy(original_wm_path, str(extracted_path))
        except ValueError:
            logger.warning("裁剪攻击导致提取失败，这是预期结果")
            return 0.0

    def _contrast_test(self, watermarked_path: str, original_wm_path: str,
                       wm_dims: Tuple[int, int]) -> float:
        """对比度调整攻击测试"""
        img = cv2.imread(watermarked_path)

        # 对比度和亮度调整参数
        contrast_factor = 1.4
        brightness_offset = 15
        enhanced_img = cv2.convertScaleAbs(img, alpha=contrast_factor, beta=brightness_offset)

        attacked_path = self.output_dir / "attacked_contrast.png"
        extracted_path = self.output_dir / "extracted_contrast.png"

        cv2.imwrite(str(attacked_path), enhanced_img)
        self.extractor.extract_watermark_from_image(str(attacked_path), wm_dims, str(extracted_path))
        return self.analyzer.compute_pixel_accuracy(original_wm_path, str(extracted_path))

    def _compression_test(self, watermarked_path: str, original_wm_path: str,
                          wm_dims: Tuple[int, int]) -> float:
        """JPEG压缩攻击测试"""
        img = cv2.imread(watermarked_path)

        attacked_path = self.output_dir / "attacked_compression.jpg"
        extracted_path = self.output_dir / "extracted_compression.png"

        # 80%质量的JPEG压缩
        compression_quality = 80
        cv2.imwrite(str(attacked_path), img, [cv2.IMWRITE_JPEG_QUALITY, compression_quality])
        self.extractor.extract_watermark_from_image(str(attacked_path), wm_dims, str(extracted_path))
        return self.analyzer.compute_pixel_accuracy(original_wm_path, str(extracted_path))

    def _generate_test_report(self):
        """生成测试报告"""
        report_path = self.output_dir / "robustness_test_report.json"
        report_data = {
            'timestamp': datetime.now().isoformat(),
            'test_results': self.test_results,
            'summary': {
                'total_tests': len(self.test_results),
                'average_accuracy': sum(self.test_results.values()) / len(self.test_results),
                'best_performance': max(self.test_results.items(), key=lambda x: x[1]),
                'worst_performance': min(self.test_results.items(), key=lambda x: x[1])
            }
        }

        try:
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
            logger.info(f"测试报告已生成: {report_path}")
        except Exception as e:
            logger.error(f"生成测试报告失败: {e}")


class WatermarkSystemCLI:
    """命令行界面控制器"""

    def __init__(self):
        self.embedder = LSBWatermarkEmbedder()
        self.extractor = LSBWatermarkExtractor()
        self.test_suite = RobustnessTestSuite()

    def setup_argument_parser(self) -> argparse.ArgumentParser:
        """设置命令行参数解析器"""
        main_parser = argparse.ArgumentParser(
            description="增强型数字水印系统 - 支持LSB嵌入、提取和鲁棒性分析",
            formatter_class=argparse.RawDescriptionHelpFormatter
        )

        subparsers = main_parser.add_subparsers(dest="operation", required=True, help="操作模式")

        # 嵌入命令
        embed_cmd = subparsers.add_parser("embed", help="在图像中嵌入数字水印")
        embed_cmd.add_argument("-s", "--source", required=True, help="源图像文件路径")
        embed_cmd.add_argument("-w", "--watermark", required=True, help="水印图像文件路径")
        embed_cmd.add_argument("-d", "--destination", required=True, help="输出图像文件路径")

        # 提取命令
        extract_cmd = subparsers.add_parser("extract", help="从图像中提取数字水印")
        extract_cmd.add_argument("-s", "--source", required=True, help="含水印的图像文件路径")
        extract_cmd.add_argument("-d", "--destination", required=True, help="提取水印的输出路径")
        extract_cmd.add_argument("--height", type=int, required=True, help="原始水印高度")
        extract_cmd.add_argument("--width", type=int, required=True, help="原始水印宽度")

        # 测试命令
        test_cmd = subparsers.add_parser("test", help="执行鲁棒性测试分析")
        test_cmd.add_argument("-s", "--source", required=True, help="含水印的图像文件路径")
        test_cmd.add_argument("-w", "--watermark", required=True, help="原始水印图像路径（用于对比）")
        test_cmd.add_argument("--height", type=int, required=True, help="原始水印高度")
        test_cmd.add_argument("--width", type=int, required=True, help="原始水印宽度")

        return main_parser

    def execute_embedding_operation(self, args) -> bool:
        """执行水印嵌入操作"""
        logger.info("开始执行水印嵌入操作")
        return self.embedder.embed_watermark_in_image(args.source, args.watermark, args.destination)

    def execute_extraction_operation(self, args) -> bool:
        """执行水印提取操作"""
        logger.info("开始执行水印提取操作")
        return self.extractor.extract_watermark_from_image(
            args.source, (args.height, args.width), args.destination
        )

    def execute_testing_operation(self, args) -> bool:
        """执行鲁棒性测试操作"""
        logger.info("开始执行鲁棒性测试操作")
        try:
            results = self.test_suite.execute_comprehensive_tests(
                args.source, args.watermark, (args.height, args.width)
            )

            print("\n=== 鲁棒性测试结果汇总 ===")
            for test_name, accuracy in results.items():
                print(f"{test_name:<25}: {accuracy:>6.2f}%")

            average_score = sum(results.values()) / len(results)
            print(f"{'平均准确率':<25}: {average_score:>6.2f}%")
            print("=" * 40)

            return True
        except Exception as e:
            logger.error(f"鲁棒性测试执行失败: {e}")
            return False

    def run(self):
        """运行主程序"""
        parser = self.setup_argument_parser()
        args = parser.parse_args()

        try:
            if args.operation == "embed":
                success = self.execute_embedding_operation(args)
            elif args.operation == "extract":
                success = self.execute_extraction_operation(args)
            elif args.operation == "test":
                success = self.execute_testing_operation(args)
            else:
                logger.error(f"未知操作: {args.operation}")
                success = False

            if success:
                logger.info("操作执行成功")
                return 0
            else:
                logger.error("操作执行失败")
                return 1

        except KeyboardInterrupt:
            logger.info("用户中断操作")
            return 1
        except Exception as e:
            logger.error(f"程序执行过程中发生未处理的错误: {e}")
            return 1


if __name__ == "__main__":
    """程序入口点"""
    cli_controller = WatermarkSystemCLI()
    exit_code = cli_controller.run()
    exit(exit_code)