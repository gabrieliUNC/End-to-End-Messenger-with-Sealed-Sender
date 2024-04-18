//
//  Item.swift
//  iOS Front End
//
//  Created by Ethan Rayala on 4/18/24.
//

import Foundation
import SwiftData

@Model
final class Item {
    var timestamp: Date
    
    init(timestamp: Date) {
        self.timestamp = timestamp
    }
}
