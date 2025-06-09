//
//  Models.swift
//
//
//  Created by Itay Brenner on 28/8/24.
//

import Foundation

enum VideoQuality: Float {
  case very_high = 0.9
  case high = 0.85
  case medium = 0.7
  case low = 0.5
  case very_low = 0.3
}

enum VideoEncoding: String {
  case h264 = "h264"
  case hevc = "hevc"
}
