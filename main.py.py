import pandas as pd
import csv

class SimpleNSLKDDProcessor:
    def __init__(self):
        self.csv_filename = None
        self.data = None
        self.feature_names = [
            'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
            'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
            'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
            'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
            'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
            'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
            'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
            'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
            'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
            'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'attack_type', 'difficulty_level'
        ]
        
    def step1_load_real_csv(self, filename):
        self.csv_filename = filename
        
        try:
            # Load the actual NSL-KDD dataset
            self.data = pd.read_csv(filename, names=self.feature_names)
            
            print("Data loaded successfully from:", filename)
            print("Shape:", self.data.shape)
            print("Total records:", len(self.data))
            print("Total features:", len(self.data.columns))
            
            return True
            
        except Exception as e:
            print("Error loading data:", str(e))
            print("Make sure your file path is correct")
            return False
    
    def step2_read_and_print_csv(self, num_lines=10):
        if self.data is None:
            print("No data loaded. Run step1_load_real_csv() first.")
            return
        
        print("Reading first", num_lines, "lines from:", self.csv_filename)
        print("-" * 80)
        
        # Print header
        print("Headers:")
        for i, header in enumerate(self.feature_names):
            print(f"  {i+1}. {header}")
        print()
        
        # Print first few data rows
        print("First", num_lines, "data rows:")
        for i in range(min(num_lines, len(self.data))):
            print(f"Line {i+1}:")
            row = self.data.iloc[i]
            for j, value in enumerate(row):
                print(f"  {self.feature_names[j]}: {value}")
            print()
        
        print("-" * 80)
        print("Data preview complete")
    
    def step3_extract_values(self):
        if self.data is None:
            print("No data loaded. Run step1_load_real_csv() first.")
            return
        
        print("Extracting and analyzing values from NSL-KDD dataset")
        print("-" * 80)
        
        # Basic statistics
        print("Dataset summary:")
        print("  Total samples:", len(self.data))
        print("  Total features:", len(self.data.columns))
        
        # Attack type distribution
        print("\nAttack type distribution:")
        attack_counts = self.data['attack_type'].value_counts()
        for attack_type, count in attack_counts.head(10).items():
            print(f"  {attack_type}: {count}")
        
        # Protocol type distribution
        print("\nProtocol type distribution:")
        protocol_counts = self.data['protocol_type'].value_counts()
        for protocol, count in protocol_counts.items():
            print(f"  {protocol}: {count}")
        
        # Basic feature statistics
        print("\nNumerical features sample (first 5 rows):")
        numerical_features = ['duration', 'src_bytes', 'dst_bytes', 'count', 'srv_count']
        for feature in numerical_features:
            if feature in self.data.columns:
                values = self.data[feature].head().tolist()
                print(f"  {feature}: {values}")
        
        print("\nValue extraction complete")
        return True
    
    def step4_simple_prediction_function(self):
        def always_normal():
            return "normal"
        
        def always_attack():
            return "attack"
        
        print("Testing simple prediction functions on real data:")
        print("-" * 50)
        
        # Test with actual data samples
        if self.data is not None:
            test_samples = self.data.head(5)
            
            print("Function 1 (always_normal):")
            for i, (idx, row) in enumerate(test_samples.iterrows()):
                prediction = always_normal()
                actual = row['attack_type']
                print(f"  Sample {i+1}: Predicted={prediction}, Actual={actual}")
            
            print("\nFunction 2 (always_attack):")
            for i, (idx, row) in enumerate(test_samples.iterrows()):
                prediction = always_attack()
                actual = row['attack_type']
                print(f"  Sample {i+1}: Predicted={prediction}, Actual={actual}")
        
        print("\nSimple prediction functions created")
        return always_normal, always_attack
    
    def step5_input_based_prediction(self):
        def simple_rule_classifier(protocol_type, src_bytes, dst_bytes, service):
            # Rules based on common NSL-KDD attack patterns
            if protocol_type == "icmp":
                return "attack"  # Many ICMP attacks in NSL-KDD
            elif src_bytes == 0 and dst_bytes == 0:
                return "attack"  # Often scanning attempts
            elif service == "private":
                return "attack"  # Private service often indicates attacks
            elif src_bytes > 10000 or dst_bytes > 10000:
                return "normal"  # Large data transfers usually normal
            else:
                return "normal"
        
        print("Testing input-based prediction function on real NSL-KDD data:")
        print("-" * 70)
        
        if self.data is not None:
            test_samples = self.data.head(10)
            
            correct_predictions = 0
            total_predictions = 0
            
            for i, (idx, row) in enumerate(test_samples.iterrows()):
                protocol = row['protocol_type']
                src_bytes = row['src_bytes']
                dst_bytes = row['dst_bytes']
                service = row['service']
                actual = row['attack_type']
                
                prediction = simple_rule_classifier(protocol, src_bytes, dst_bytes, service)
                
                # Check if prediction is correct (simplified)
                actual_binary = "normal" if actual == "normal" else "attack"
                is_correct = prediction == actual_binary
                if is_correct:
                    correct_predictions += 1
                total_predictions += 1
                
                print(f"Sample {i+1}:")
                print(f"  Protocol: {protocol}, Src: {src_bytes}, Dst: {dst_bytes}, Service: {service}")
                print(f"  Predicted: {prediction}, Actual: {actual}, Correct: {is_correct}")
                print()
            
            accuracy = correct_predictions / total_predictions
            print(f"Simple accuracy on {total_predictions} samples: {accuracy:.2f}")
        
        print("Input-based prediction function created")
        return simple_rule_classifier
    
    def step6_simple_linear_classifier(self):
        class SimpleLinearClassifier:
            def __init__(self):
                # Weights for different features
                self.weight_duration = 0.1
                self.weight_src_bytes = 0.0001
                self.weight_dst_bytes = 0.0001
                self.weight_count = 0.01
                self.threshold = 1.0
                
            def predict(self, duration, src_bytes, dst_bytes, count):
                score = (self.weight_duration * duration + 
                        self.weight_src_bytes * src_bytes +
                        self.weight_dst_bytes * dst_bytes +
                        self.weight_count * count)
                
                if score > self.threshold:
                    return "attack"
                else:
                    return "normal"
            
            def update_weights(self, new_duration_w, new_src_w, new_dst_w, new_count_w, new_threshold):
                self.weight_duration = new_duration_w
                self.weight_src_bytes = new_src_w
                self.weight_dst_bytes = new_dst_w
                self.weight_count = new_count_w
                self.threshold = new_threshold
                
                print("Updated parameters:")
                print(f"  duration weight: {self.weight_duration}")
                print(f"  src_bytes weight: {self.weight_src_bytes}")
                print(f"  dst_bytes weight: {self.weight_dst_bytes}")
                print(f"  count weight: {self.weight_count}")
                print(f"  threshold: {self.threshold}")
        
        print("Testing simple linear classifier on real NSL-KDD data:")
        print("-" * 70)
        
        classifier = SimpleLinearClassifier()
        
        if self.data is not None:
            test_samples = self.data.head(8)
            
            print("Initial predictions:")
            correct_initial = 0
            for i, (idx, row) in enumerate(test_samples.iterrows()):
                duration = row['duration']
                src_bytes = row['src_bytes']
                dst_bytes = row['dst_bytes']
                count = row['count']
                actual = row['attack_type']
                
                prediction = classifier.predict(duration, src_bytes, dst_bytes, count)
                score = (classifier.weight_duration * duration + 
                        classifier.weight_src_bytes * src_bytes +
                        classifier.weight_dst_bytes * dst_bytes +
                        classifier.weight_count * count)
                
                actual_binary = "normal" if actual == "normal" else "attack"
                is_correct = prediction == actual_binary
                if is_correct:
                    correct_initial += 1
                
                print(f"Sample {i+1}: dur={duration}, src={src_bytes}, dst={dst_bytes}, cnt={count}")
                print(f"  Score: {score:.3f}, Predicted: {prediction}, Actual: {actual}")
            
            initial_accuracy = correct_initial / len(test_samples)
            print(f"Initial accuracy: {initial_accuracy:.2f}")
            
            print("\n" + "-" * 40)
            print("Updating parameters...")
            classifier.update_weights(0.05, 0.0002, 0.0002, 0.02, 0.5)
            
            print("\nPredictions after parameter update:")
            correct_updated = 0
            for i, (idx, row) in enumerate(test_samples.iterrows()):
                duration = row['duration']
                src_bytes = row['src_bytes']
                dst_bytes = row['dst_bytes']
                count = row['count']
                actual = row['attack_type']
                
                prediction = classifier.predict(duration, src_bytes, dst_bytes, count)
                score = (classifier.weight_duration * duration + 
                        classifier.weight_src_bytes * src_bytes +
                        classifier.weight_dst_bytes * dst_bytes +
                        classifier.weight_count * count)
                
                actual_binary = "normal" if actual == "normal" else "attack"
                is_correct = prediction == actual_binary
                if is_correct:
                    correct_updated += 1
                
                print(f"Sample {i+1}: dur={duration}, src={src_bytes}, dst={dst_bytes}, cnt={count}")
                print(f"  Score: {score:.3f}, Predicted: {prediction}, Actual: {actual}")
            
            updated_accuracy = correct_updated / len(test_samples)
            print(f"Updated accuracy: {updated_accuracy:.2f}")
        
        print("\nSimple linear classifier with learnable parameters created")
        return classifier
    
    def run_complete_simple_pipeline(self, dataset_path):
        print("Starting Simple Step-by-Step Pipeline with Real NSL-KDD Data")
        print("Dataset path:", dataset_path)
        print("=" * 80)
        
        print("\nSTEP 1: Loading real NSL-KDD CSV file")
        if not self.step1_load_real_csv(dataset_path):
            print("Failed to load dataset. Please check the file path.")
            return None
        
        input("\nPress Enter to continue to Step 2...")
        
        print("\nSTEP 2: Reading and printing CSV content")
        self.step2_read_and_print_csv(5)  # Show first 5 records
        
        input("\nPress Enter to continue to Step 3...")
        
        print("\nSTEP 3: Extracting and analyzing values")
        self.step3_extract_values()
        
        input("\nPress Enter to continue to Step 4...")
        
        print("\nSTEP 4: Creating simple prediction functions")
        self.step4_simple_prediction_function()
        
        input("\nPress Enter to continue to Step 5...")
        
        print("\nSTEP 5: Creating input-based prediction function")
        self.step5_input_based_prediction()
        
        input("\nPress Enter to continue to Step 6...")
        
        print("\nSTEP 6: Creating simple linear classifier")
        classifier = self.step6_simple_linear_classifier()
        
        print("\n" + "=" * 80)
        print("PIPELINE COMPLETE - WORKING WITH REAL NSL-KDD DATA")
        print("You now have:")
        print("  - Real NSL-KDD dataset loaded and analyzed")
        print("  - Functions to read and process the actual data")
        print("  - Simple prediction functions tested on real samples")
        print("  - A basic linear classifier with learnable parameters")
        print("  - Performance metrics on actual NSL-KDD data")
  
        
        return classifier

def main():
    print("Starting with real NSL-KDD dataset...")
    
    dataset_path = r"C:\Users\Admin\test\KDDTrain+.csv"
    processor = SimpleNSLKDDProcessor()
    classifier = processor.run_complete_simple_pipeline(dataset_path)
    
    return processor, classifier

if __name__ == "__main__":
    processor, classifier = main()
