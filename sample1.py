import pandas as pd
import csv

class SimpleNSLKDDProcessor:
    def __init__(self):
        self.csv_filename = None
        self.data = None
        
    def step1_create_toy_csv(self, filename="toy.csv"):
        self.csv_filename = filename
        
        sample_data = [
            [0, "tcp", "http", "SF", 239, 486, 0, "normal"],
            [0, "tcp", "http", "SF", 235, 1337, 0, "normal"], 
            [0, "udp", "private", "SF", 105, 146, 0, "neptune"],
            [2, "tcp", "ftp", "SF", 0, 0, 0, "normal"],
            [0, "icmp", "ecr_i", "SF", 1032, 0, 0, "smurf"],
            [0, "tcp", "http", "REJ", 0, 0, 0, "ipsweep"],
            [1, "tcp", "telnet", "SF", 52, 1124, 0, "normal"],
            [0, "tcp", "smtp", "SF", 23, 455, 0, "guess_passwd"]
        ]
        
        headers = ["duration", "protocol_type", "service", "flag", 
                  "src_bytes", "dst_bytes", "land", "attack_type"]
        
        with open(filename, 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(headers)
            writer.writerows(sample_data)
        
        print("Created toy CSV file:", filename)
        print("Contains", len(sample_data), "sample records")
        return filename
    
    def step2_read_and_print_csv(self):
        if not self.csv_filename:
            print("No CSV file created yet. Run step1_create_toy_csv() first.")
            return
        
        print("Reading CSV file:", self.csv_filename)
        print("-" * 50)
        
        with open(self.csv_filename, 'r') as file:
            reader = csv.reader(file)
            for line_num, line in enumerate(reader, 1):
                print("Line", line_num, ":", line)
        
        print("-" * 50)
        print("File reading complete")
    
    def step3_extract_values(self):
        if not self.csv_filename:
            print("No CSV file created yet. Run step1_create_toy_csv() first.")
            return
        
        print("Extracting values from:", self.csv_filename)
        print("-" * 50)
        
        data_rows = []
        with open(self.csv_filename, 'r') as file:
            reader = csv.reader(file)
            headers = next(reader)
            
            print("Headers:", headers)
            print()
            
            for row_num, row in enumerate(reader, 1):
                print("Row", row_num, ":")
                for i, value in enumerate(row):
                    print("  ", headers[i], ":", value)
                print()
                data_rows.append(row)
        
        self.data = {'headers': headers, 'rows': data_rows}
        print("Extracted", len(data_rows), "data rows")
        return self.data
    
    def step4_simple_prediction_function(self):
        def always_normal():
            return "normal"
        
        def always_attack():
            return "attack"
        
        print("Testing simple prediction functions:")
        print("-" * 50)
        
        print("Function 1 (always_normal):")
        for i in range(3):
            prediction = always_normal()
            print("  Prediction", i+1, ":", prediction)
        
        print()
        print("Function 2 (always_attack):")
        for i in range(3):
            prediction = always_attack()
            print("  Prediction", i+1, ":", prediction)
        
        print()
        print("Simple prediction functions created")
        return always_normal, always_attack
    
    def step5_input_based_prediction(self):
        def simple_rule_classifier(protocol_type, src_bytes, dst_bytes):
            if protocol_type == "icmp":
                return "attack"
            elif src_bytes == 0 and dst_bytes == 0:
                return "attack"
            elif src_bytes > 1000 or dst_bytes > 1000:
                return "normal"
            else:
                return "normal"
        
        print("Testing input-based prediction function:")
        print("-" * 50)
        
        if self.data:
            for i, row in enumerate(self.data['rows'][:5]):
                protocol = row[1]
                src_bytes = int(row[4])
                dst_bytes = int(row[5])
                actual = row[7]
                
                prediction = simple_rule_classifier(protocol, src_bytes, dst_bytes)
                print("Row", i+1, ":", protocol, ",", src_bytes, ",", dst_bytes)
                print("  Predicted:", prediction, ", Actual:", actual)
                print()
        
        print("Input-based prediction function created")
        return simple_rule_classifier
    
    def step6_simple_linear_classifier(self):
        class SimpleLinearClassifier:
            def __init__(self):
                self.weight_src_bytes = 0.001
                self.weight_dst_bytes = 0.001
                self.threshold = 500
                
            def predict(self, src_bytes, dst_bytes):
                score = (self.weight_src_bytes * src_bytes + 
                        self.weight_dst_bytes * dst_bytes)
                
                if score > self.threshold:
                    return "normal"
                else:
                    return "attack"
            
            def update_weights(self, new_src_weight, new_dst_weight, new_threshold):
                self.weight_src_bytes = new_src_weight
                self.weight_dst_bytes = new_dst_weight
                self.threshold = new_threshold
                print("Updated parameters:")
                print("  src_bytes weight:", self.weight_src_bytes)
                print("  dst_bytes weight:", self.weight_dst_bytes)
                print("  threshold:", self.threshold)
        
        print("Testing simple linear classifier:")
        print("-" * 50)
        
        classifier = SimpleLinearClassifier()
        
        if self.data:
            print("Initial predictions:")
            for i, row in enumerate(self.data['rows'][:3]):
                src_bytes = int(row[4])
                dst_bytes = int(row[5])
                actual = row[7]
                
                prediction = classifier.predict(src_bytes, dst_bytes)
                score = classifier.weight_src_bytes * src_bytes + classifier.weight_dst_bytes * dst_bytes
                
                print("Row", i+1, ": src=", src_bytes, ", dst=", dst_bytes)
                print("  Score:", round(score, 2), ", Predicted:", prediction, ", Actual:", actual)
            
            print()
            print("-" * 30)
            print("Updating parameters...")
            classifier.update_weights(0.002, 0.0005, 300)
            
            print()
            print("Predictions after parameter update:")
            for i, row in enumerate(self.data['rows'][:3]):
                src_bytes = int(row[4])
                dst_bytes = int(row[5])
                actual = row[7]
                
                prediction = classifier.predict(src_bytes, dst_bytes)
                score = classifier.weight_src_bytes * src_bytes + classifier.weight_dst_bytes * dst_bytes
                
                print("Row", i+1, ": src=", src_bytes, ", dst=", dst_bytes)
                print("  Score:", round(score, 2), ", Predicted:", prediction, ", Actual:", actual)
        
        print()
        print("Simple linear classifier with learnable parameters created")
        return classifier
    
    def run_complete_simple_pipeline(self):
        print("Starting Simple Step-by-Step Pipeline")
        print("=" * 60)
        
        print()
        print("STEP 1: Creating toy CSV file")
        self.step1_create_toy_csv()
        
        input("Press Enter to continue to Step 2...")
        
        print()
        print("STEP 2: Reading and printing CSV content")
        self.step2_read_and_print_csv()
        
        input("Press Enter to continue to Step 3...")
        
        print()
        print("STEP 3: Extracting individual values")
        self.step3_extract_values()
        
        input("Press Enter to continue to Step 4...")
        
        print()
        print("STEP 4: Creating simple prediction functions")
        self.step4_simple_prediction_function()
        
        input("Press Enter to continue to Step 5...")
        
        print()
        print("STEP 5: Creating input-based prediction function")
        self.step5_input_based_prediction()
        
        input("Press Enter to continue to Step 6...")
        
        print()
        print("STEP 6: Creating simple linear classifier")
        classifier = self.step6_simple_linear_classifier()
        
        print()
        print("=" * 60)
        print("SIMPLE PIPELINE COMPLETE")
        print("You now have:")
        print("  - A toy CSV dataset")
        print("  - Functions to read and process the data")
        print("  - Simple prediction functions")
        print("  - A basic linear classifier with learnable parameters")
        print()
        print("Next steps: Gradually add more features and complexity")
        
        return classifier

def main():
    print("Starting with elementary approach...")
    
    processor = SimpleNSLKDDProcessor()
    classifier = processor.run_complete_simple_pipeline()
    
    return processor, classifier

if __name__ == "__main__":
    processor, classifier = main()