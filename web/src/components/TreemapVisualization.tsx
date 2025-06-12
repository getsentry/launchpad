import React from 'react';
import ReactECharts from 'echarts-for-react';
import { TreemapType } from '../types/treemap';
import type { TreemapElement, TreemapResults, EChartsTreemapData } from '../types/treemap';

interface TreemapVisualizationProps {
  data: TreemapResults;
  sizeMode: 'install' | 'download';
}

// Color mapping for different element types
const TYPE_COLORS: Record<TreemapType, string> = {
  [TreemapType.FILES]: '#3498db',
  [TreemapType.EXECUTABLES]: '#e74c3c',
  [TreemapType.RESOURCES]: '#2ecc71',
  [TreemapType.ASSETS]: '#f39c12',
  [TreemapType.MANIFESTS]: '#9b59b6',
  [TreemapType.SIGNATURES]: '#1abc9c',
  [TreemapType.FRAMEWORKS]: '#e67e22',
  [TreemapType.PLISTS]: '#34495e',
  [TreemapType.DEX_FILES]: '#f1c40f',
  [TreemapType.NATIVE_LIBRARIES]: '#8e44ad',
  [TreemapType.COMPILED_RESOURCES]: '#16a085',
  [TreemapType.MODULES]: '#2980b9',
  [TreemapType.CLASSES]: '#27ae60',
  [TreemapType.METHODS]: '#d35400',
  [TreemapType.STRINGS]: '#c0392b',
  [TreemapType.SYMBOLS]: '#7f8c8d',
  [TreemapType.DYLD]: '#fd79a8',
  [TreemapType.MACHO]: '#fdcb6e',
  [TreemapType.FUNCTION_STARTS]: '#6c5ce7',
  [TreemapType.CODE_SIGNATURE]: '#a29bfe',
  [TreemapType.EXTERNAL_METHODS]: '#fd79a8',
  [TreemapType.DEX_CLASSES]: '#00b894',
  [TreemapType.DEX_METHODS]: '#00cec9',
  [TreemapType.NATIVE_CODE]: '#74b9ff',
  [TreemapType.OTHER]: '#636e72',
  [TreemapType.UNMAPPED]: '#95a5a6',
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

  const data: EChartsTreemapData = {
    name: element.name,
    value: size,
    itemStyle: {
      color: element.element_type ? TYPE_COLORS[element.element_type] : TYPE_COLORS[TreemapType.OTHER],
    },
    label: {
      show: true,
      position: 'inside',
    },
  };

  if (element.children && element.children.length > 0) {
    data.children = element.children
      .filter(child => {
        const childSize = sizeMode === 'install' ? child.install_size : child.download_size;
        return childSize > 0;
      })
      .map(child => convertToEChartsData(child, sizeMode));
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
    },
    tooltip: {
      trigger: 'item',
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
        },
        itemStyle: {
          borderColor: '#fff',
          borderWidth: 2,
        },
        levels: [
          {
            itemStyle: {
              borderColor: '#777',
              borderWidth: 0,
              gapWidth: 1,
            },
          },
          {
            itemStyle: {
              borderColor: '#555',
              borderWidth: 5,
              gapWidth: 1,
            },
            emphasis: {
              itemStyle: {
                borderColor: '#ddd',
              },
            },
          },
          {
            itemStyle: {
              borderColor: '#333',
              borderWidth: 5,
              gapWidth: 1,
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
