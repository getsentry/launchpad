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
      color: color,
    },
    label: {
      show: true,
      position: 'inside',
    },
    upperLabel: {
      show: true,
      backgroundColor: color,
      color: COLORS.white,
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
    title: {
      text: `${data.platform.toUpperCase()} Size Analysis - ${sizeMode === 'install' ? 'Install' : 'Download'} Size`,
      subtext: `Total: ${formatBytes(totalSize)} | Files: ${data.file_count}`,
      left: 'center',
      textStyle: {
        fontSize: 18,
        fontWeight: 'bold',
        color: COLORS.gray500,
        fontFamily: 'Rubik',
      },
      subtextStyle: {
        fontSize: 14,
        color: COLORS.gray400,
        fontFamily: 'Rubik',
      },
    },
    tooltip: {
      trigger: 'item',
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
        visibleMin: 300,
        label: {
          show: true,
          formatter: '{b}',
          position: 'inside',
          fontSize: 12,
          fontWeight: 'bold',
          color: COLORS.white,
          fontFamily: 'Rubik',
        },
        itemStyle: {
          borderColor: COLORS.white,
          borderWidth: 1,
        },
        levels: [
          {
            // Root level - minimal styling
            itemStyle: {
              borderColor: COLORS.gray200,
              borderWidth: 0,
              gapWidth: 1,
            },
            upperLabel: {
              show: true,
              height: 24,
              fontSize: 13,
              fontWeight: 'bold',
              color: COLORS.white,
              backgroundColor: COLORS.red300,
              borderRadius: 3,
              padding: [4, 8],
              fontFamily: 'Rubik',
            },
            label: {
              show: true,
              position: 'inside',
              fontSize: 12,
              fontWeight: 'bold',
              color: COLORS.white,
              fontFamily: 'Rubik',
            },
          },
          {
            // First level - category groups
            itemStyle: {
              borderColor: COLORS.gray300,
              borderWidth: 1,
              gapWidth: 1,
            },
            upperLabel: {
              show: true,
              height: 20,
              fontSize: 12,
              fontWeight: 'bold',
              color: COLORS.white,
              backgroundColor: COLORS.red300,
              borderRadius: 2,
              padding: [3, 6],
              fontFamily: 'Rubik',
            },
            label: {
              show: true,
              position: 'inside',
              fontSize: 11,
              fontWeight: 'bold',
              color: COLORS.white,
              fontFamily: 'Rubik',
            },
            emphasis: {
              itemStyle: {
                borderColor: COLORS.gray400,
                borderWidth: 2,
              },
            },
          },
          {
            // Second level - individual files
            itemStyle: {
              borderColor: COLORS.gray100,
              borderWidth: 1,
              gapWidth: 1,
            },
            upperLabel: {
              show: true,
              height: 18,
              fontSize: 10,
              fontWeight: 'normal',
              color: COLORS.white,
              backgroundColor: COLORS.red300,
              borderRadius: 2,
              padding: [2, 4],
              fontFamily: 'Rubik',
            },
            label: {
              show: true,
              position: 'inside',
              fontSize: 10,
              color: COLORS.white,
              fontFamily: 'Rubik',
            },
            emphasis: {
              itemStyle: {
                borderColor: COLORS.gray300,
                borderWidth: 2,
              },
            },
          },
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
        opts={{ renderer: 'svg' }}
      />
    </div>
  );
};

export default TreemapVisualization;
