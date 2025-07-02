import ReactECharts from 'echarts-for-react';
import React from 'react';
import type { EChartsTreemapData, TreemapElement, TreemapResults } from '../types/treemap';
import { TreemapType } from '../types/treemap';

interface TreemapVisualizationProps {
  data: TreemapResults;
  sizeMode: 'install' | 'download';
}

// Sentry color constants, see: https://develop.sentry.dev/frontend/component-library/
const COLORS = {
  // Base colors
  gray900: '#0F0C13',
  gray700: '#1E1825',
  gray500: '#2D2435', 
  gray300: '#4A3B57',
  gray200: '#ddd',
  gray100: '#E8E2ED',
  
  border: 'rgba(0, 0, 0, 0.8)',

  purple: 'rgba(117, 83, 255, 0.7))',
  indigo: 'rgba(90, 32, 188, 0.56)',
  pink: 'rgba(245, 58, 159, 0.5)',
  salmon: 'rgba(252, 116, 111, 0.5)',
  orange: 'rgba(255, 152, 56, 0.5)',
  kiwi: 'rgba(186, 206, 5, 0.5)',
  cyan: 'rgba(0, 169, 210, 0.5)',

  white: '#FFFFFF',
} as const;

const TYPE_COLORS: Record<TreemapType, string> = {
  // File Types
  [TreemapType.FILES]: COLORS.purple,
  [TreemapType.EXECUTABLES]: COLORS.purple,
  [TreemapType.RESOURCES]: COLORS.purple,
  [TreemapType.ASSETS]: COLORS.purple,
  
  // Platform Assets
  [TreemapType.MANIFESTS]: COLORS.indigo,
  [TreemapType.SIGNATURES]: COLORS.indigo,
  [TreemapType.FONTS]: COLORS.indigo,
  
  // iOS Specific
  [TreemapType.FRAMEWORKS]: COLORS.pink,
  [TreemapType.PLISTS]: COLORS.pink,
  [TreemapType.DYLD]: COLORS.pink,
  [TreemapType.MACHO]: COLORS.pink,
  [TreemapType.FUNCTION_STARTS]: COLORS.pink,
  [TreemapType.CODE_SIGNATURE]: COLORS.pink,
  
  // Android Specific
  [TreemapType.DEX_FILES]: COLORS.kiwi,
  [TreemapType.NATIVE_LIBRARIES]: COLORS.kiwi,
  [TreemapType.COMPILED_RESOURCES]: COLORS.kiwi,
  
  // Binary Analysis
  [TreemapType.MODULES]: COLORS.cyan,
  [TreemapType.CLASSES]: COLORS.cyan,
  [TreemapType.METHODS]: COLORS.cyan,
  [TreemapType.STRINGS]: COLORS.cyan,
  [TreemapType.SYMBOLS]: COLORS.cyan,
  [TreemapType.EXTERNAL_METHODS]: COLORS.cyan,
  
  // Catch-all
  [TreemapType.OTHER]: COLORS.cyan,
  [TreemapType.UNMAPPED]: COLORS.cyan,
};

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function convertToEChartsData(
  element: TreemapElement,
  sizeMode: 'install' | 'download'
): EChartsTreemapData {
  const size = sizeMode === 'install' ? element.install_size : element.download_size;
  const color = element.element_type ? TYPE_COLORS[element.element_type] : TYPE_COLORS[TreemapType.OTHER];

  let children: EChartsTreemapData[] | undefined;
  let totalSize = size;

  if (element.children && element.children.length > 0) {
    children = element.children.map(child => convertToEChartsData(child, sizeMode));
    // Calculate total size from children for directories
    if (element.is_directory) {
      totalSize = children.reduce((sum, child) => sum + (child.value || 0), 0);
    }
  }

  const data: EChartsTreemapData = {
    name: element.name,
    value: totalSize,
    itemStyle: {
      borderColor: color,
      borderRadius: 4
    },
    label: {
      show: true,
      position: 'inside',
      formatter: '{b}',
      fontSize: 12,
      fontWeight: 'bold',
      color: COLORS.white,
      fontFamily: 'Rubik',
    },
    upperLabel: {
      show: true,
      color: COLORS.white,
      height: 24,
      fontSize: 12,
      fontWeight: 'bold',
      borderRadius: [2, 2, 0, 0],
      padding: [2, 2],
      fontFamily: 'Rubik',
    },
  };

  if (children) {
    data.children = children;
  }

  return data;
}

export const TreemapVisualization: React.FC<TreemapVisualizationProps> = ({
  data,
  sizeMode
}) => {
  const chartData = convertToEChartsData(data.root, sizeMode);
  const totalSize = sizeMode === 'install' ? data.total_install_size : data.total_download_size;

  const option = {
    tooltip: {
      trigger: 'item',
      borderWidth: 0,
      backgroundColor: COLORS.white,
      borderColor: COLORS.gray200,
      borderWidth: 1,
      hideDelay: 0,
      transitionDuration: 0,
      padding: 12,
      extraCssText: 'border-radius: 6px;',
      textStyle: {
        color: COLORS.gray500,
        fontFamily: 'Rubik',
      },
      formatter: function (info: { name: string; value: number }) {
        const value = info.value;
        const percent = ((value / totalSize) * 100).toFixed(2);
        return `
          <div>
            <div style="display: flex; align-items: center; font-size: 12px; font-family: Rubik; font-weight: bold; line-height: 1;">
              <div style="width: 8px; height: 8px; border-radius: 50%; background-color: ${info.data?.itemStyle?.borderColor || COLORS.gray300}; margin-right: 4px;"></div>
              <span style="color: ${COLORS.gray300}">File Type</span>
            </div>
            <div style="font-family: Rubik; line-height: 1;">
              <p style="font-size: 14px; font-weight: bold; margin-bottom: -2px;">${info.name}</p>
              <p style="font-size: 12px; margin-bottom: -4px;">Size: ${formatBytes(value)}</p>
              <p style="font-size: 12px;">Percentage: ${percent}%</p>
            </div>
          </div>
        `;
      },
    },
    series: [
      {
        name: 'Size Analysis',
        type: 'treemap',
        animationEasing: 'quarticOut',
        animationDuration: 300,
        height: `100%`,
        width: `100%`,
        breadcrumb: {
          show: false,
          left: '0',
          top: '0',
          emphasis: {
            itemStyle: {
              color: COLORS.white,
              textStyle: {
                fontSize: 12,
                fontWeight: 'bold',
                fontFamily: 'Rubik',
                color: COLORS.gray500,
              },
            },
          },
          itemStyle: {
            textStyle: {
              fontSize: 12,
              fontWeight: 'bold',
              fontFamily: 'Rubik',
              color: COLORS.gray500,
            },
          },
        },
        zoomToNodeRatio: 0.1,
        visibleMin: 300,
        itemStyle: {
          borderWidth: 6,
        },
        levels: [
          {
            itemStyle: {
              gapWidth: 4,
            }
          },
          {
            colorSaturation: [0.2, 0.4],
            itemStyle: {
              gapWidth: 2
            }
          },
          {
            colorSaturation: [0.3, 0.5],
            itemStyle: {
              borderColorSaturation: 0.6,
              gapWidth: 2
            }
          },
          {
            colorSaturation: [0.3, 0.5],
            itemStyle: {
              borderColorSaturation: 0.6,
              gapWidth: 1
            }
          },
          {
            colorSaturation: [0.3, 0.5],
            itemStyle: {
              borderColor: COLORS.white,
              borderColorSaturation: 0.6,
              gapWidth: 1
            }
          }
        ],
        data: chartData.children || [chartData],
      },
    ],
  };

  return (
    <div style={{ width: '100%', height: '600px' }}>
      <ReactECharts
        option={option}
        style={{ height: '100%', width: '100%' }}
        opts={{ renderer: 'canvas' }}
      />
    </div>
  );
};

export default TreemapVisualization;
