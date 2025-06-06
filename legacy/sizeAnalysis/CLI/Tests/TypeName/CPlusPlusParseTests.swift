//
//  File.swift
//
//
//  Created by Noah Martin on 7/20/21.
//

import Foundation
import XCTest

@testable import Shared

class ParseTests: XCTestCase {

  func testParseBasicFunction() {
    let symbol = "swift::getRootSuperclass()"
    print(symbol)
    CPlusPlusParser.parse(symbol: symbol).prettyPrint()
  }

  func testOneFunctionParam() {
    let symbol = "swift::defaultInitCallback(void*)"
    print(symbol)
    CPlusPlusParser.parse(symbol: symbol).prettyPrint()
  }

  func testGenericAndParam() {
    let symbol = "swift::Lazy<ConformanceState>::defaultInitCallback(void*)"
    print(symbol)
    CPlusPlusParser.parse(symbol: symbol).prettyPrint()
  }

  func testSpaceInParam() {
    let symbol = "std::__1::__throw_length_error(char const*)"
    print(symbol)
    CPlusPlusParser.parse(symbol: symbol).prettyPrint()
  }

  func testSpaceAtRoot() {
    let symbol = "ComScore::File::exists() const"
    print(symbol)
    CPlusPlusParser.parse(symbol: symbol).prettyPrint()
  }

  func testTwoSpaces() {
    let symbol = "ComScore::File::moveInternal(ComScore::File const&) const"
    print(symbol)
    CPlusPlusParser.parse(symbol: symbol).prettyPrint()
  }

  func testMultipleGenerics() {
    let symbol = "swift::Lazy<ConformanceState, Test2>::defaultInitCallback(void*)"
    print(symbol)
    CPlusPlusParser.parse(symbol: symbol).prettyPrint()
  }

  func testSpaceAfterGeneric() {
    let symbol =
      "ComScore::String::String(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > const&) const"
    print(symbol)
    CPlusPlusParser.parse(symbol: symbol).prettyPrint()
  }

  func testWithObjcMethodName() {
    let symbol =
      "std::__1::priority_queue<spotify::palette::ColorCube, std::__1::vector<spotify::palette::ColorCube, std::__1::allocator<spotify::palette::ColorCube> >, +[SPTColorCutQuantizer swatchesByQuantizingPixelsFromColorCube:toMaxColorsCount:]::$_2>::push(spotify::palette::ColorCube&&)"
    print(symbol)
    CPlusPlusParser.parse(symbol: symbol).prettyPrint()
  }

  func testGmsWithParenthesis() {
    let symbol =
      "gmscore::vector::GMSContour gmscore::vector::GMSContourList::Append<gmscore::model::Point2D const*, int const*>(gmscore::model::Point2D const*, gmscore::model::Point2D const*, int const*, int const*, unsigned int) (.cold.1)"
    print(symbol)
    let parsed = CPlusPlusParser.parse(symbol: symbol)
    assert(!parsed.cannonicalSymbol.path.isEmpty)
  }
}
