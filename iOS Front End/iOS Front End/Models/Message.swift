//
//  Message.swift
//  iOS Front End
//
//  Created by Ethan Rayala on 4/18/24.
//

import Foundation

struct Message: Identifiable, Codable {
    var id: String
    var text: String
    var received: Bool
    var timestamp: Date
}
