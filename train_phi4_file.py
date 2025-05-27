import wandb
from huggingface_hub import login
from unsloth import FastLanguageModel
from unsloth.chat_templates import get_chat_template, train_on_responses_only
from unsloth import is_bfloat16_supported
from datasets import Dataset
import pickle
from transformers import TrainingArguments, DataCollatorForSeq2Seq
from trl import SFTTrainer
import torch


def main():
    # Initialize logging
    # wandb.login(key="")
    # wandb.init(project="phi4")
    # login(token="")

    # Model configuration
    max_seq_length = 8000
    load_in_4bit = True

    # Load model and tokenizer
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name="unsloth/Phi-4",
        max_seq_length=max_seq_length,
        load_in_4bit=load_in_4bit,
    )

    # Add LoRA adapters
    model = FastLanguageModel.get_peft_model(
        model,
        r=8,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                        "gate_proj", "up_proj", "down_proj"],
        lora_alpha=8,
        lora_dropout=0,
        bias="none",
        use_gradient_checkpointing="unsloth",
        random_state=3407,
    )

    # Load dataset
    try:
        with open('../dataset/file_level/file_propmt_with_explain.pkl', 'rb') as file:
            prompts = pickle.load(file)
    except FileNotFoundError:
        raise Exception("Prompt file not found. Please check the file path.")

    # Set up chat template
    tokenizer = get_chat_template(tokenizer, chat_template="phi-4")

    # Format entire dataset
    def format_examples(examples):
        formatted = []
        for example in examples:
            messages = [
                {"role": "system", "content": example[0]['instruction']},
                {"role": "user", "content": example[1]['input']},
                {"role": "assistant", "content": example[2]['output']}
            ]
            formatted.append({"messages": messages})
        return {
            "text": [tokenizer.apply_chat_template(convo["messages"], tokenize=False)
                     for convo in formatted]
        }

    formatted_data = format_examples(prompts)
    full_dataset = Dataset.from_dict(formatted_data)

    # Training setup
    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        train_dataset=full_dataset,  # Use full dataset
        dataset_text_field="text",
        max_seq_length=max_seq_length,
        data_collator=DataCollatorForSeq2Seq(tokenizer=tokenizer),
        packing=False,
        args=TrainingArguments(
            per_device_train_batch_size=2,
            gradient_accumulation_steps=4,
            warmup_steps=5,
            num_train_epochs=3,
            learning_rate=2e-4,
            fp16=not is_bfloat16_supported(),
            bf16=is_bfloat16_supported(),
            logging_steps=1,
            optim="adamw_8bit",
            weight_decay=0.01,
            lr_scheduler_type="linear",
            seed=3407,
            output_dir="outputs",
            report_to="wandb",
            # Removed evaluation parameters
        ),
    )

    # Train on responses only
    trainer = train_on_responses_only(
        trainer,
        instruction_part="<|im_start|>user<|im_sep|>",
        response_part="<|im_start|>assistant<|im_sep|>",
    )

    # Start training
    trainer.train()

    # Save model
    print("Publishing model to Hugging Face Hub...")
    model.push_to_hub_gguf("Kei5uke/Phi4_file_explain_v2",
                           tokenizer, quantization_method=["q8_0"])


if __name__ == "__main__":
    main()
