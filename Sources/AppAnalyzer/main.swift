//
//  main.swift
//  AppAnalyzer
//
//  Created by CLI Generator
//

import ArgumentParser
import Foundation
import Logging

// MARK: - Logging Setup

let logger = Logger(label: "com.emerge.appanalyzer")

// MARK: - CLI Command Structure

@main
struct AppAnalyzer: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "app-analyzer",
        abstract: "Analyze iOS/macOS app bundles and generate detailed size reports.",
        version: "1.0.0",
        subcommands: [AnalyzeCommand.self],
        defaultSubcommand: AnalyzeCommand.self
    )
}

struct AnalyzeCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "analyze",
        abstract: "Analyze an app bundle and generate a JSON report."
    )
    
    // MARK: - CLI Arguments
    
    @Argument(help: "Path to the app bundle (.app) or zip file to analyze")
    var inputPath: String
    
    @Option(name: .shortAndLong, help: "Output path for the JSON analysis report")
    var output: String = "analysis-report.json"
    
    @Option(name: .long, help: "Working directory for temporary files")
    var workingDir: String?
    
    @Flag(name: .long, help: "Enable verbose logging")
    var verbose: Bool = false
    
    @Flag(name: .long, help: "Skip Swift metadata parsing for faster analysis")
    var skipSwiftMetadata: Bool = false
    
    @Flag(name: .long, help: "Skip instruction disassembly")
    var skipInstructionDisassembly: Bool = false
    
    // MARK: - Execution
    
    mutating func run() throws {
        configureLogging()
        
        let startTime = ProcessInfo.processInfo.systemUptime
        
        do {
            try validateInputs()
            let results = try analyzeApp()
            try writeResults(results)
            
            let endTime = ProcessInfo.processInfo.systemUptime
            logger.info("Analysis completed successfully in \(String(format: "%.2f", endTime - startTime))s")
            
        } catch {
            logger.error("Analysis failed: \(error)")
            throw ExitCode.failure
        }
    }
    
    // MARK: - Helper Methods
    
    private func configureLogging() {
        LoggingSystem.bootstrap { label in
            var handler = StreamLogHandler.standardOutput(label: label)
            handler.logLevel = verbose ? .debug : .info
            return handler
        }
    }
    
    private func validateInputs() throws {
        let inputURL = URL(fileURLWithPath: inputPath)
        
        guard FileManager.default.fileExists(atPath: inputURL.path) else {
            throw AnalysisError.inputFileNotFound(inputPath)
        }
        
        // Check if it's a supported file type
        let pathExtension = inputURL.pathExtension.lowercased()
        guard pathExtension == "app" || pathExtension == "zip" || pathExtension == "ipa" else {
            throw AnalysisError.unsupportedFileType(pathExtension)
        }
        
        // Ensure output directory exists
        let outputURL = URL(fileURLWithPath: output)
        let outputDir = outputURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: outputDir, withIntermediateDirectories: true)
        
        logger.info("Input: \(inputPath)")
        logger.info("Output: \(output)")
    }
    
    private func analyzeApp() throws -> AnalysisResults {
        logger.info("Starting analysis...")
        
        let inputURL = URL(fileURLWithPath: inputPath)
        let analyzer = AppBundleAnalyzer(
            inputPath: inputURL,
            workingDirectory: workingDir,
            skipSwiftMetadata: skipSwiftMetadata,
            skipInstructionDisassembly: skipInstructionDisassembly
        )
        
        return try analyzer.analyze()
    }
    
    private func writeResults(_ results: AnalysisResults) throws {
        logger.info("Writing analysis results...")
        
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        
        let data = try encoder.encode(results)
        let outputURL = URL(fileURLWithPath: output)
        try data.write(to: outputURL)
        
        logger.info("Results written to: \(output)")
        logger.info("Total app size: \(ByteCountFormatter.string(fromByteCount: Int64(results.totalSize), countStyle: .file))")
    }
}

// MARK: - Error Types

enum AnalysisError: LocalizedError {
    case inputFileNotFound(String)
    case unsupportedFileType(String)
    case analysisFailure(String)
    
    var errorDescription: String? {
        switch self {
        case .inputFileNotFound(let path):
            return "Input file not found: \(path)"
        case .unsupportedFileType(let type):
            return "Unsupported file type: .\(type). Supported types: .app, .zip, .ipa"
        case .analysisFailure(let message):
            return "Analysis failed: \(message)"
        }
    }
}