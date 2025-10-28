import matplotlib.pyplot as plt
import numpy as np

def create_comparison_graphs():
    """Create visual comparison graphs"""
    
    # Data from testing
    honeypots = ['Baseline', 'LLM v1', 'LLM v2\nHybrid']
    latencies = [0, 3250, 773]
    costs = [0, 1.40, 0.11]
    variability = [0, 90, 40]
    
    fig, axes = plt.subplots(1, 3, figsize=(15, 5))
    
    # Graph 1: Latency
    axes[0].bar(honeypots, latencies, color=['green', 'red', 'orange'])
    axes[0].set_title('Average Latency (ms)', fontsize=14, fontweight='bold')
    axes[0].set_ylabel('Milliseconds')
    for i, v in enumerate(latencies):
        axes[0].text(i, v + 100, str(v), ha='center', fontweight='bold')
    
    # Graph 2: Cost
    axes[1].bar(honeypots, costs, color=['green', 'red', 'orange'])
    axes[1].set_title('Cost per 1000 Requests ($)', fontsize=14, fontweight='bold')
    axes[1].set_ylabel('USD')
    for i, v in enumerate(costs):
        axes[1].text(i, v + 0.05, f'${v:.2f}', ha='center', fontweight='bold')
    
    # Graph 3: Variability
    axes[2].bar(honeypots, variability, color=['red', 'green', 'orange'])
    axes[2].set_title('Response Variability (%)', fontsize=14, fontweight='bold')
    axes[2].set_ylabel('Percent')
    for i, v in enumerate(variability):
        axes[2].text(i, v + 2, f'{v}%', ha='center', fontweight='bold')
    
    plt.tight_layout()
    plt.savefig('honeypot_comparison.png', dpi=300, bbox_inches='tight')
    print("Graph saved as: honeypot_comparison.png")
    plt.show()

if __name__ == '__main__':
    create_comparison_graphs()