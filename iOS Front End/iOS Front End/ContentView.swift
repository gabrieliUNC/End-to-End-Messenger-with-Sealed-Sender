//
//  ContentView.swift
//  iOS Front End
//
//  Created by Ethan Rayala on 4/18/24.
//

import SwiftUI
import SwiftData

struct ContentView: View {
    var messageArray = ["Hello", "wassup", "not much g just chillin", "that's cool"]
    var body: some View {
        VStack {
            TitleRow()
            
            ScrollView {
                ForEach(messageArray, id: \.self) { text in
                    MessageBubble(message: Message(id: "12345", text: text, received: true, timestamp: Date()))
                }
            }
            .padding(.top, 10)
            .background(.white)
//            .cornerRadius(30, corners: [.topLeft, .topRight])
        }
    }
}

#Preview {
    ContentView()
        .modelContainer(for: Item.self, inMemory: true)
}
