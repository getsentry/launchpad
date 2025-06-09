//
//  File.swift
//
//
//  Created by Noah Martin on 2/11/21.
//

import CwlDemangle
import XCTest

@testable import Shared

class DemangleTests: XCTestCase {
  func testExtensionName() {
    let name =
      "_$s17BehanceFoundation8RGBColorV0A0E7uiColorACSo7UIColorC_tc33_9E27401A9AADA838B7C80696B26310CFLlfC"
    let symbol = try! CwlDemangle.parseMangledSwiftSymbol(name)
    XCTAssertEqual(symbol.module, "Behance")
    XCTAssertEqual(symbol.typeName, "RGBColor")
  }

  func testOptional() {
    let name = "_$s17BehanceFoundation8RGBColorVSgWOd"
    let symbol = try! CwlDemangle.parseMangledSwiftSymbol(name)
    XCTAssertEqual(symbol.module, "BehanceFoundation")
    XCTAssertEqual(symbol.typeName, "RGBColor")
  }

  func testDefaultArgument() {
    let name =
      "_$s17BehanceFoundation13NetworkSearchV5query7content4sort13creativeField8location3tag9timestamp4tool5color6school6camera4lens8exposure11focalLength19restrictToGIFImagesACSS_AA7ContentOAA0cD4SortVAA0cd8CreativeI0VSgAA0cD5PlaceVSgSSSg0B04DateVAA4ToolVSgAA8RGBColorVSgAA6SchoolVSgAA6CameraVSgAA4LensVSgAA8ExposureVSgAA05FocalT0VSgSbtcfcfA1_"
    let symbol = try! CwlDemangle.parseMangledSwiftSymbol(name)
    XCTAssertEqual(symbol.module, "BehanceFoundation")
    XCTAssertEqual(symbol.typeName, "NetworkSearch")
  }

  func testProtocolConformance() {
    let name = "_$s21SPTCommonLocalization22CommonPluralizedStringOSHAASQWb"
    let symbol = try! CwlDemangle.parseMangledSwiftSymbol(name)
    XCTAssertEqual(symbol.module, "SPTCommonLocalization")
    XCTAssertEqual(symbol.testName, ["SPTCommonLocalization", "CommonPluralizedString"])
  }

  func testLazyProtocolWitnessTable() {
    let name = "_$s21SPTCommonLocalization22CommonPluralizedStringOACSQAAWl"
    let symbol = try! CwlDemangle.parseMangledSwiftSymbol(name)
    XCTAssertEqual(symbol.module, "SPTCommonLocalization")
    XCTAssertEqual(symbol.testName, ["SPTCommonLocalization", "CommonPluralizedString"])
    print(symbol)
  }

  func testCMU() {
    let name = "_$s6Airbnb14AppCoordinatorCMU"
    let symbol = try! CwlDemangle.parseMangledSwiftSymbol(name)
    XCTAssertEqual(symbol.module, "Airbnb")
    XCTAssertEqual(symbol.typeName, "AppCoordinator")
  }

  func testFunction() {
    let name =
      "_$s7Behance010ThisWeekOnA6RouterC04thiscdA14ViewController_26didRequestToOpenProjectsAtyAA0bcdagH0C_SitF"
    let symbol = try! CwlDemangle.parseMangledSwiftSymbol(name)
    XCTAssertEqual(symbol.module, "Behance")
    XCTAssertEqual(symbol.typeName, "ThisWeekOnBehanceRouter")
  }

  func testGetter() {
    let name = "_$s7Behance21LiveStreamSectionTypeO10shortTitleSSSgvg"
    let symbol = try! CwlDemangle.parseMangledSwiftSymbol(name)
    XCTAssertEqual(symbol.module, "Behance")
    XCTAssertEqual(symbol.typeName, "LiveStreamSectionType")
  }

  func testFunctionInFunction() {
    let name =
      "_$s7Behance35SearchResultsProjectCardsDataSourceC15requestProjects13ignoringCacheySb_tF21handleSuccessResponseL_yyAA0d4CardN0VF"
    let symbol = try! CwlDemangle.parseMangledSwiftSymbol(name)
    XCTAssertEqual(symbol.module, "Behance")
    XCTAssertEqual(symbol.typeName, "SearchResultsProjectCardsDataSource")
  }

  func testTypeMetadataAccessor() {
    let name = "_$s7Behance5Class33_780234778D36763DCF101B798353C492LLCMa"
    let symbol = try! CwlDemangle.parseMangledSwiftSymbol(name)
    XCTAssertEqual(symbol.module, "Behance")
    XCTAssertEqual(symbol.typeName, "Class")
  }
}
