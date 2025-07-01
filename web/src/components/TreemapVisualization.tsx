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
  // Grays
  gray500: '#2B2233',
  gray400: '#3E3446',
  gray300: '#71637E',
  gray200: '#E0DCE5',
  gray100: '#F0ECF3',

  // Purples
  purple400: '#6559C5',
  purple300: '#6C5FC7',

  // Blues
  blue400: '#2562D4',
  blue300: '#3C74DD',

  // Greens
  green400: '#207964',
  green300: '#2BA185',

  // Yellows
  yellow400: '#856C00',
  yellow300: '#EBC000',

  // Reds
  red400: '#CF2126',
  red300: '#F55459',

  // Pinks
  pink400: '#D1056B',
  pink300: '#F14499',

  // Whites
  white: '#FFFFFF',
} as const;

const TYPE_COLORS: Record<TreemapType, string> = {
  [TreemapType.FILES]: COLORS.blue400,
  [TreemapType.EXECUTABLES]: COLORS.purple400, // binary breakdown
  [TreemapType.RESOURCES]: COLORS.blue300, // asset catalog
  [TreemapType.ASSETS]: COLORS.blue400, // asset catalog
  [TreemapType.FONTS]: COLORS.green300,
  [TreemapType.MANIFESTS]: COLORS.purple400,
  [TreemapType.SIGNATURES]: COLORS.blue300,
  [TreemapType.FRAMEWORKS]: COLORS.red300,
  [TreemapType.PLISTS]: COLORS.gray400,
  [TreemapType.DEX_FILES]: COLORS.pink400,
  [TreemapType.NATIVE_LIBRARIES]: COLORS.purple400,
  [TreemapType.COMPILED_RESOURCES]: COLORS.blue300, // asset catalog
  [TreemapType.MODULES]: COLORS.blue300,
  [TreemapType.CLASSES]: COLORS.purple300, // binary breakdown
  [TreemapType.METHODS]: COLORS.purple400, // binary breakdown
  [TreemapType.STRINGS]: COLORS.purple300, // binary breakdown
  [TreemapType.SYMBOLS]: COLORS.purple400, // binary breakdown
  [TreemapType.DYLD]: COLORS.pink300,
  [TreemapType.MACHO]: COLORS.purple300, // binary breakdown
  [TreemapType.FUNCTION_STARTS]: COLORS.purple300, // binary breakdown
  [TreemapType.CODE_SIGNATURE]: COLORS.blue400,
  [TreemapType.EXTERNAL_METHODS]: COLORS.pink300,
  [TreemapType.DEX_CLASSES]: COLORS.purple300, // binary breakdown
  [TreemapType.DEX_METHODS]: COLORS.purple400, // binary breakdown
  [TreemapType.NATIVE_CODE]: COLORS.blue300,
  [TreemapType.OTHER]: COLORS.gray300,
  [TreemapType.UNMAPPED]: COLORS.gray200,
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
      position: 'inside',
      backgroundColor: COLORS.white,
      borderColor: COLORS.gray200,
      borderWidth: 1,
      textStyle: {
        color: COLORS.gray500,
        fontFamily: 'Rubik',
      },
      formatter: function (info: { name: string; value: number }) {
        const value = info.value;
        const percent = ((value / totalSize) * 100).toFixed(2);
        return `
          <div style="padding: 8px;">
            <strong>${info.name}</strong><br/>
            Size: ${formatBytes(value)}<br/>
            Percentage: ${percent}%
          </div>
        `;
      },
    },
    series: [
      {
        name: 'Size Analysis',
        type: 'treemap',
        animationEasing: 'quarticOut',
        animationDuration: 500,
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
                color: COLORS.gray400,
              },
            },
          },
          itemStyle: {
            textStyle: {
              fontSize: 12,
              fontWeight: 'bold',
              fontFamily: 'Rubik',
              color: COLORS.gray400,
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
