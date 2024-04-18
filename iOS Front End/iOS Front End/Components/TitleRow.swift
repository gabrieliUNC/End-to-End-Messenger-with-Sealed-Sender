//
//  TitleRow.swift
//  iOS Front End
//
//  Created by Ethan Rayala on 4/18/24.
//

import SwiftUI

struct TitleRow: View {
    var name = "John Doe"
    
    var body: some View {
        HStack(spacing: 20) {
            Image(systemName: "person.circle")
                    .aspectRatio(contentMode: .fill)
                    .frame(width: 50, height: 50)
                    .cornerRadius(50)
            VStack(alignment: .leading) {
                Text(name)
                    .font(.title).bold()
                
                Text("Online")
                    .font(.caption)
                    .foregroundColor(.gray)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding()
    }
}

struct TitleRow_Previews: PreviewProvider {
    static var previews: some View {
        TitleRow()
    }
}
